"""honey_allowlist.py — 显式 allowlist + 预期流量基线 + 噪声预算 KPI

蜜罐最贵的失败不是漏报，是变成噪声源：运维一旦把告警静音，归因链就断了。
Thinkst 的运营基准是「数百个 canary ≈ 4 告警/年」——不是检测精度，是**噪声预算**。

浮世已有「未签发 token 只记 noise」，但那是在**事后**降噪；缺的是**前置放行**：
已知合法源（漏扫 / 爬虫 / 备份 / DLP / 监控）在进判定之前就该被摘掉，而不是让
它们先把 noise 计数打满，再靠人眼分辨。

两条设计红线：

  1. allowlist 必须**显式**。只认写下来的 CIDR + 类目（scanner/crawler/backup/
     dlp/monitor），不做 UA 或行为启发式。启发式一误判，就等于替攻击者开后门——
     把真实攻击当扫描器静音，而且静音是无声的，没人会发现。

  2. CIDR 不得宽于 /24（IPv6 /64）。`0.0.0.0/0`、`10.0.0.0/8` 一律拒绝：
     一个跑在 10.1.2.3 的实例若被 /8 覆盖，整个内网的证据全部静音。
     同理，覆盖蜜罐自己 bind 地址的网段默认也拒绝——那等于把「和我同网段的
     攻击者」全部静音，而攻击者最可能就出现在那里。

噪声预算不是仪表盘装饰，它回答一个运营问题：**这个蜜罐还值得开着吗？**
超预算 = token 放置位置不对（放在攻击者不经过的地方，只会被合法流量蹭到），
正确动作是审 placement，不是关告警。
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

# 最大允许的网段宽度：IPv4 /24、IPv6 /64。
# 写成「前缀长度下限」而不是「掩码上限」，因为 ipaddress 的 prefixlen 越大网段越小。
MAX_PREFIX_V4 = 24
MAX_PREFIX_V6 = 64

# 显式类目。没有 "other"：类目不明的源不该进 allowlist，
# 因为「我不知道它是什么」正是需要它继续告警的理由。
RULE_KINDS = ("scanner", "crawler", "backup", "dlp", "monitor")

# Thinkst 运营基准：数百 canary ≈ 4 告警/年 → 0.01 告警/蜜标/年。
THINKST_REF = {"canaries": 400, "alerts_per_year": 4.0}


class AllowlistError(ValueError):
    """规则不合法。刻意抛错而不是静默忽略：错的 allowlist 比没有 allowlist 更危险。"""


@dataclass(frozen=True)
class Rule:
    cidr: str
    kind: str
    note: str
    ports: tuple[int, ...] | None = None      # None = 全部端口
    ua_like: str | None = None                # 可选的显式 UA 子串（不是启发式，是写死的）
    _net: object = field(default=None, repr=False, compare=False)

    def covers(self, addr) -> bool:
        return addr in self._net

    def to_dict(self) -> dict:
        return {"cidr": self.cidr, "kind": self.kind, "note": self.note,
                "ports": list(self.ports) if self.ports else None, "ua_like": self.ua_like}


@dataclass(frozen=True)
class Decision:
    """一次准入判断。allowed=False 时 kind 为空 —— 调用方只需看 allowed。"""
    allowed: bool
    kind: str = ""
    reason: str = ""
    rule_cidr: str = ""

    def __bool__(self) -> bool:
        return self.allowed


def parse_cidr(spec: str) -> object:
    """解析并**收紧**一条网段声明。宽于 /24（v6 /64）直接拒绝。

    裸 IP 视作 /32（v6 /128）—— 单机放行是最常见也最安全的形态。
    """
    s = (spec or "").strip()
    if not s:
        raise AllowlistError("空 CIDR")
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError as e:
        raise AllowlistError(f"无法解析 {spec!r}：{e}") from e
    if net.version == 4:
        if net.prefixlen < MAX_PREFIX_V4:
            raise AllowlistError(
                f"{spec!r} 覆盖 /{net.prefixlen}，宽于允许的 /{MAX_PREFIX_V4}："
                f"网段越宽越可能把真实攻击者一起放行（{net.num_addresses} 个地址）")
    else:
        if net.prefixlen < MAX_PREFIX_V6:
            raise AllowlistError(
                f"{spec!r} 覆盖 /{net.prefixlen}，宽于允许的 /{MAX_PREFIX_V6}")
    if net.num_addresses > 256 and net.version == 4:
        # /24 正好 256；上面已拦，这里只是双保险
        raise AllowlistError(f"{spec!r} 地址数 {net.num_addresses} 超限")
    return net


def _addr(ip: str):
    """把来源串规范成 ip_address。IPv4-mapped IPv6（::ffff:1.2.3.4）折叠回 v4，
    否则双栈监听下同一条规则会漏判。"""
    a = ipaddress.ip_address((ip or "").strip())
    if a.version == 6 and a.ipv4_mapped is not None:
        return a.ipv4_mapped
    return a


class Allowlist:
    """显式放行表。先声明的先生效（不做「更具体优先」的隐式排序——
    隐式排序会让人无法从文本上预测结果，运营上不可审计）。"""

    def __init__(self, bind_ip: str | None = None):
        self.rules: list[Rule] = []
        self.bind_ip = bind_ip
        self.stats = {"checked": 0, "allowed": 0, "denied": 0}

    def add(self, cidr: str, kind: str, note: str, ports=None, ua_like: str | None = None,
            allow_self: bool = False) -> Rule:
        if kind not in RULE_KINDS:
            raise AllowlistError(f"类目 {kind!r} 不在 {RULE_KINDS} 内：类目必须可解释")
        if not (note or "").strip():
            raise AllowlistError("每条规则必须写 note（谁、为什么）—— 半年后没人记得 IP 是谁")
        net = parse_cidr(cidr)
        if ports is not None:
            ports = tuple(sorted({int(p) for p in ports}))
            for p in ports:
                if not 0 < p < 65536:
                    raise AllowlistError(f"端口 {p} 越界")
        if self.bind_ip and not allow_self:
            try:
                b = _addr(self.bind_ip)
            except ValueError:
                b = None
            # 0.0.0.0 / :: 是「所有地址」，不是某个具体网段，不参与自遮蔽判断
            if b is not None and not b.is_unspecified and b.version == net.version and b in net:
                raise AllowlistError(
                    f"{cidr!r} 覆盖蜜罐自己的监听地址 {self.bind_ip}："
                    f"同网段的攻击者会一起被静音。确需如此请显式传 allow_self=True")
        rule = Rule(cidr=str(net), kind=kind, note=note.strip(), ports=ports,
                    ua_like=ua_like, _net=net)
        self.rules.append(rule)
        return rule

    def check(self, ip: str, port: int | None = None, ua: str | None = None) -> Decision:
        self.stats["checked"] += 1
        try:
            a = _addr(ip)
        except ValueError:
            self.stats["denied"] += 1
            return Decision(False, reason=f"来源 {ip!r} 不是合法 IP")
        for r in self.rules:
            if r._net.version != a.version or not r.covers(a):
                continue
            if r.ports is not None and port is not None and int(port) not in r.ports:
                continue
            if r.ua_like and r.ua_like not in (ua or ""):
                continue
            self.stats["allowed"] += 1
            return Decision(True, kind=r.kind, rule_cidr=r.cidr,
                            reason=f"{r.kind}: {r.note}")
        self.stats["denied"] += 1
        return Decision(False, reason="无匹配规则 → 按真实流量处理")

    def __len__(self) -> int:
        return len(self.rules)

    def to_dict(self) -> dict:
        return {"rules": [r.to_dict() for r in self.rules], "stats": dict(self.stats)}

    @classmethod
    def from_specs(cls, specs: list[dict], bind_ip: str | None = None) -> "Allowlist":
        al = cls(bind_ip=bind_ip)
        for s in specs:
            al.add(**s)
        return al


class NoiseBudget:
    """预期流量基线 + 噪声预算 KPI。

    「告警」= 一个带 token 的硬命中（canary / oob alert）。
    「噪声」= 未签发 token、路径乱撞、allowlist 之外的探针。
    两者的比值才是可运营指标：只有告警为零、噪声爆炸，说明蜜标形状泄露但没人中招；
    只有噪声为零、告警为零，说明这个蜜罐根本没被看见（放置问题）。
    """

    def __init__(self, canaries: int = 14, alerts_per_year: float | None = None,
                 baseline_noise_per_day: float = 2.0, window_days: float = 30.0):
        self.canaries = max(1, int(canaries))
        if alerts_per_year is None:
            # 按 Thinkst 比例缩小到本实例规模；下限 1.0 —— 0.14 告警/年不可行动，
            # 运营上等于「没有预算」，超了也不知道该不该管。
            alerts_per_year = max(1.0, round(
                THINKST_REF["alerts_per_year"] / THINKST_REF["canaries"] * self.canaries, 3))
        self.alerts_per_year = float(alerts_per_year)
        self.baseline_noise_per_day = float(baseline_noise_per_day)
        self.window_days = float(window_days)
        self.events: list[dict] = []     # {ts, verdict, token?}

    def record(self, verdict: str, token: str | None = None, detail: str = "",
               ts: float | None = None) -> None:
        self.events.append({"ts": ts if ts is not None else time.time(),
                            "verdict": verdict, "token": token, "detail": detail[:200]})

    # 便捷入口，与 server 侧的三个判定点一一对应
    def alert(self, token: str = "", detail: str = "", ts: float | None = None) -> None:
        self.record("alert", token, detail, ts)

    def noise(self, detail: str = "", token: str | None = None,
              ts: float | None = None) -> None:
        self.record("noise", token, detail, ts)

    def allowlisted(self, detail: str = "", ts: float | None = None) -> None:
        self.record("allowlisted", None, detail, ts)

    def report(self, now: float | None = None) -> dict:
        now = now if now is not None else time.time()
        lo = now - self.window_days * 86400.0
        win = [e for e in self.events if lo <= e["ts"] <= now]
        alerts = [e for e in win if e["verdict"] == "alert"]
        noise = [e for e in win if e["verdict"] == "noise"]
        allow = [e for e in win if e["verdict"] == "allowlisted"]
        tokens = {e["token"] for e in alerts if e.get("token")}

        # 观测窗口：有事件就用「首个事件→now」，否则用整个配置窗口
        t0 = min((e["ts"] for e in win), default=lo)
        elapsed_days = max((now - t0) / 86400.0, 1e-9)
        elapsed_years = elapsed_days / 365.25
        projected = len(alerts) / elapsed_years if elapsed_days >= 1.0 else float(len(alerts))
        reliable = elapsed_days >= 7.0

        if not reliable:
            status = "INSUFFICIENT-DATA"
        elif projected > self.alerts_per_year:
            status = "OVER"
        elif projected > self.alerts_per_year * 0.7:
            status = "WATCH"
        else:
            status = "OK"

        noise_per_day = len(noise) / elapsed_days if elapsed_days > 0 else 0.0
        dev = noise_per_day / self.baseline_noise_per_day if self.baseline_noise_per_day else 0.0
        total = len(alerts) + len(noise)
        ratio = (len(noise) / total) if total else 0.0

        advice: list[str] = []
        if status == "OVER":
            advice.append("告警超预算：先审 token 放置（是否在合法流量必经路径上），不要关告警")
        if dev > 3.0:
            advice.append(f"噪声 {noise_per_day:.1f}/天 ≈ 基线 {self.baseline_noise_per_day:.1f}"
                          f" 的 {dev:.1f}×：蜜标位置可能已被索引/扫描器收录")
        if ratio > 0.9 and len(alerts) == 0:
            advice.append("只有噪声没有告警：蜜标形状可能已泄露，或工件不在攻击者必经路径")
        if len(alerts) == 0 and len(noise) == 0:
            advice.append("零流量：放置问题（令牌是工件不是服务，得摆到有人走的地方）")
        if len(allow) and len(allow) > len(noise):
            advice.append(f"allowlist 吞掉 {len(allow)} 次事件：确认这些源确实是自己的扫描/备份")

        return {
            "window_days": self.window_days,
            "elapsed_days": round(elapsed_days, 3),
            "reliable": reliable,
            "alerts": len(alerts), "distinct_tokens": len(tokens),
            "noise": len(noise), "allowlisted": len(allow),
            "projected_alerts_per_year": round(projected, 2),
            "budget_alerts_per_year": self.alerts_per_year,
            "budget_status": status,
            "noise_per_day": round(noise_per_day, 2),
            "baseline_noise_per_day": self.baseline_noise_per_day,
            "baseline_deviation": round(dev, 2),
            "noise_ratio": round(ratio, 3),
            "advice": advice,
        }

    def kpi_line(self, now: float | None = None) -> str:
        r = self.report(now)
        return (f"KPI {r['budget_status']}　告警 {r['alerts']}（投影 "
                f"{r['projected_alerts_per_year']}/年 vs 预算 {r['budget_alerts_per_year']}）"
                f"　噪声 {r['noise']}（{r['noise_per_day']}/天，基线 "
                f"{r['baseline_noise_per_day']}）　放行 {r['allowlisted']}")
