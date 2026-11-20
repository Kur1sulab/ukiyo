#!/usr/bin/env python3
"""自测：显式 allowlist（CIDR ≤ /24）+ 噪声预算 KPI

allowlist 是蜜罐里最容易写错、错了又最难发现的东西：写宽了等于给攻击者开后门
（真实攻击被静默），写错了没人报错（只是「最近没告警」）。所以这个自测的重点
不是「能匹配」，是**收口**和**可观测**：

  1. 收口：0.0.0.0/0、/8、/23、IPv6 /48、覆盖自己监听地址的网段，全部必须被拒。
  2. 匹配：/24 边界精确、端口限定生效、IPv4-mapped IPv6 折叠、非法 IP 不算放行。
  3. 端到端 A/B：同一条攻击链打两台实例，白名单那台**对外响应完全相同**
     （状态码一致，对方无法反推自己被放行），但账本里只有 allowlist 事件、
     oob 告警为零；对照组三面全响。
  4. 噪声预算：Thinkst 比例可复算、超预算判 OVER 并给「审放置」而不是「关告警」、
     噪声尖峰报 placement 泄露、零流量报放置问题。
  5. 配置入口：YAML 加载、JSON 加载、内置 YAML 子集（无 PyYAML 时）三条路结果一致。
  6. 配置校验硬失败：非法 CIDR、/8、覆盖 bind、未知键、缺 note、类目拼错、
     version 不认识、文件不存在 —— 全部抛错并指出**是第几条**，不许静默跳过。
  7. CLI 合并：文件规则在前、CLI 追加在后；IPv6 竖线写法；非法 CLI 硬失败。
  8. 过期：到期规则**当场**失效（不是只在加载时过滤），日期型按当天 23:59:59。
  9. 请求级前置放行：真实 HTTP 打进来，按类目计数、账本零 canary、vault 零命中、
     带外零告警，且状态接口/回放事件都能看见「被静音了多少」。
 10. CLI 层验收：`serve --help` 有全部新参数，非法配置退出码 2。

用法：python3 _selftest_allowlist.py   （全过退出码 0，任一失败退出码 1）
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honey_allowlist as al
import honey_allowlist_config as alc
import honey_demo as hd
import honey_state
from honey_server import Honeypot
from _selftest_oob import http_post, sign_v4      # 复用独立签名器，避免第三份实现漂移

HERE = os.path.dirname(os.path.abspath(__file__))

results: list[bool] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append(bool(ok))
    print(f"  [{'✅' if ok else '❌'}] {label}" + (f"　{detail}" if detail else ""))


def try_add(cidr: str, *, kind: str = "scanner", note: str = "办公网漏扫出口",
            ports=None, bind_ip: str | None = None, allow_self: bool = False) -> str | None:
    """返回错误消息（= 被拒），None 表示接受。"""
    a = al.Allowlist(bind_ip=bind_ip)
    try:
        a.add(cidr, kind, note, ports=ports, allow_self=allow_self)
        return None
    except al.AllowlistError as e:
        return str(e)


def _raises(fn, exc) -> bool:
    """只关心「有没有按预期抛错」，不吞掉别的异常类型。"""
    try:
        fn()
    except exc:
        return True
    except Exception:
        return False
    return False


def _errmsg(fn) -> str:
    """跑一个应当失败的操作，返回它报的错（一次报全的多行文本）。"""
    try:
        fn()
    except alc.ConfigError as e:
        return "\n".join(e.errors)
    return ""


# ---------------------------------------------------------------------------
# 一台实例 + 一条完整攻击链（读工件 → 回蜜标 / 签 STS / 调 MCP）
# ---------------------------------------------------------------------------
def run_chain(port: int) -> dict:
    w.portal_product  # noqa: B018 —— 只为让本函数持有 world 引用（可读性）
    base = f"http://127.0.0.1:{port}"
    c = hd.Client(base, hd.UA_AGENT)
    c.get("/")
    P = w.probe_paths()
    _, notes = c.get(f"/files/../..{P['notes']}")
    _, cfg = c.get(f"/files/../..{P['creds']}")
    _, cred = c.get(f"/files/../..{P['creds'].rsplit('/', 1)[0]}/credentials")
    _, mcp_txt = c.get("/files/../../home/ops_zhao/.config/mcp/mcp.json")
    baits = re.findall(r"/c/(c\w+)", notes)
    st_canary = c.get(f"/c/{baits[0]}")[0] if baits else 0

    akid = [ln.split("=", 1)[1].strip() for ln in cred.splitlines()
            if "aws_access_key_id" in ln][0]
    secret = [ln.split("=", 1)[1].strip() for ln in cred.splitlines()
              if "aws_secret_access_key" in ln][0]
    body = b"Action=GetCallerIdentity&Version=2011-06-15"
    hdrs = sign_v4(akid, secret, host=f"127.0.0.1:{port}", body=body)
    hdrs.pop("Signature")
    st_sts, _, _ = http_post(port, "/sts", body, hdrs)

    tok = json.loads(mcp_txt)["mcpServers"]["archiver-ops"]["headers"]["Authorization"].split()[-1]
    rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "archive.health", "arguments": {}}}).encode()
    st_mcp, _, _ = http_post(port, "/mcp", rpc,
                             {"Authorization": f"Bearer {tok}",
                              "Content-Type": "application/json"})
    return {"canary": st_canary, "sts": st_sts, "mcp": st_mcp, "bait": baits[0] if baits else ""}


w = None      # 由 main() 赋值：两台实例共享同一个 world


def main() -> int:
    global w
    w = hd.make_world()

    # ---------------------------------------------------------------
    print("\n=== 1. CIDR 收口：宽网段一律拒绝 ===")
    for cidr, why in [("0.0.0.0/0", "全世界"), ("10.0.0.0/8", "整个内网"), ("192.168.0.0/16", "整个 B 段"),
                      ("203.0.113.0/23", "两个 C 段"), ("::/0", "整个 v6"), ("2001:db8::/48", "v6 太宽")]:
        err = try_add(cidr)
        check(f"{cidr} 被拒（{why}）", err is not None, (err or "")[:72])
    check("/24 边界仍可用（不多收一格）", try_add("203.0.113.0/24") is None, "203.0.113.0/24 接受")
    check("/25 更窄当然可用", try_add("203.0.113.128/25") is None)
    check("裸 IP 视作 /32", try_add("198.51.100.7") is None, "198.51.100.7 → /32")
    check("IPv6 /64 边界可用", try_add("2001:db8:1:2::/64") is None)
    check("未声明的类目被拒", try_add("198.51.100.0/24", kind="whatever") is not None,
          "类目必须可解释")
    check("不写 note 被拒", try_add("198.51.100.0/24", note="") is not None,
          "半年后没人记得这个 IP 是谁")
    err_self = try_add("127.0.0.0/24", bind_ip="127.0.0.1")
    check("覆盖蜜罐自身监听地址的网段被拒", err_self is not None, (err_self or "")[:80])
    check("显式 allow_self=True 才放行", try_add("127.0.0.1/32", bind_ip="127.0.0.1",
                                                     allow_self=True) is None)

    # ---------------------------------------------------------------
    print("\n=== 2. 匹配语义 ===")
    a = al.Allowlist()
    a.add("203.0.113.0/24", "scanner", "办公网 Nessus 出口", ports=[443, 80])
    a.add("198.51.100.7", "backup", "Veeam 备份机")
    a.add("2001:db8:1:2::/64", "monitor", "内网 Zabbix")
    check("网段内地址放行", a.check("203.0.113.9", port=443).allowed)
    check("网段外地址不放行", not a.check("203.0.114.9", port=443).allowed)
    check("/24 边界：.255 在内", a.check("203.0.113.255", port=80).allowed)
    check("端口不在声明内 → 不放行（端口是 allowlist 的一部分）",
          not a.check("203.0.113.9", port=8080).allowed)
    check("单机规则精确命中", a.check("198.51.100.7").allowed,
          a.check("198.51.100.7").reason)
    check("相邻 IP 不误伤", not a.check("198.51.100.8").allowed)
    check("IPv4-mapped IPv6 折叠后仍命中",
          a.check("::ffff:203.0.113.9", port=443).allowed)
    check("IPv6 规则生效", a.check("2001:db8:1:2::5").allowed)
    check("非法来源按不放行处理", not a.check("not-an-ip").allowed)
    check("空表默认谁都不放行", not al.Allowlist().check("203.0.113.9").allowed,
          "安全默认：宁可多噪声，也不要悄悄静音")

    # ---------------------------------------------------------------
    print("\n=== 3. 端到端 A/B：放行只吞告警，不改对外行为 ===")
    d = tempfile.mkdtemp(prefix="ukiyo-allow-")
    # 对照组：空 allowlist
    hp_ctl = Honeypot(world=w, http_port=hd._free_port(), ssh_port=None,
                      ledger_path=os.path.join(d, "ctl.jsonl"), enable_ssh=False,
                      dns_sink=False)
    # 白名单组：把本机 127.0.0.1 当作「我们自己的漏扫出口」放行。
    # 这里显式 bind_ip=None —— 模拟实例绑在公网地址、白名单里是另一台机器，
    # 否则 127.0.0.1/32 会被自身的「遮蔽监听地址」规则拦下（见第 1 节）。
    allowed = al.Allowlist(bind_ip=None)
    allowed.add("127.0.0.1", "scanner", "办公网漏扫出口（Nessus）")
    hp_al = Honeypot(world=w, http_port=hd._free_port(), ssh_port=None,
                     ledger_path=os.path.join(d, "al.jsonl"), enable_ssh=False,
                     dns_sink=False, allowlist=allowed)
    hp_ctl.start()
    hp_al.start()
    try:
        ctl = run_chain(hp_ctl.http_port)
        got = run_chain(hp_al.http_port)

        check("对外响应完全一致（对方不能从状态码反推被放行）",
              (ctl["canary"], ctl["sts"], ctl["mcp"]) == (got["canary"], got["sts"], got["mcp"]),
              f"control={ctl['canary']}/{ctl['sts']}/{ctl['mcp']} "
              f"allowlisted={got['canary']}/{got['sts']}/{got['mcp']}")
        check("对照组：蜜标回调进账本（canary 事件）",
              any(e.get("kind") == "canary" and e.get("ctype") == "bait" for e in hp_ctl.ledger.events),
              f"control canary={sum(1 for e in hp_ctl.ledger.events if e.get('kind') == 'canary')}")
        check("白名单组：蜜标回调**不**进 canary 事件",
              not any(e.get("kind") == "canary" and e.get("ctype") == "bait"
                      for e in hp_al.ledger.events),
              f"allow canary={sum(1 for e in hp_al.ledger.events if e.get('kind') == 'canary')}")
        check("白名单组：三条链都记成 allowlist 事件（可审计）",
              sum(1 for e in hp_al.ledger.events if e.get("kind") == "allowlist") >= 3,
              f"{sum(1 for e in hp_al.ledger.events if e.get('kind') == 'allowlist')} 条，"
              f"类目 {sorted({e.get('ctype') for e in hp_al.ledger.events if e.get('kind') == 'allowlist'})}")
        check("白名单组：HTTP 蜜标仓库零命中", not hp_al.vault.hits,
              f"vault.hits={len(hp_al.vault.hits)}")
        check("白名单组：带外三面零告警", not hp_al.oob.alerts(),
              f"oob.alerts={len(hp_al.oob.alerts())}")
        check("对照组：带外三面全响（DNS 关掉了，故 aws+mcp）",
              {e["kind"] for e in hp_ctl.oob.alerts()} == {"aws", "mcp"},
              f"{sorted({e['kind'] for e in hp_ctl.oob.alerts()})}")
        r = hp_al.budget.report()
        check("噪声预算把放行单独计数（不混进噪声也不混进告警）",
              r["allowlisted"] >= 3 and r["alerts"] == 0,
              f"allowlisted={r['allowlisted']} alerts={r['alerts']} noise={r['noise']}")
    finally:
        hp_ctl.stop()
        hp_al.stop()

    # ---------------------------------------------------------------
    print("\n=== 4. 噪声预算 KPI ===")
    b400 = al.NoiseBudget(canaries=400)
    check("Thinkst 基准可复算：400 canary → 4 告警/年",
          b400.alerts_per_year == 4.0, f"{b400.alerts_per_year}/年")
    b14 = al.NoiseBudget(canaries=14)
    check("小实例按比例缩小并保住可行动下限",
          b14.alerts_per_year == 1.0, f"14 canary → {b14.alerts_per_year}/年（0.14 不可行动）")

    now = time.time()
    over = al.NoiseBudget(canaries=14)
    over.alert("t1", "aws")
    over.alert("t2", "mcp")
    for i in range(3):
        over.noise(f"scan {i}")
    ro = over.report(now + 30 * 86400)
    check("30 天内 2 次告警 → 判 OVER（投影 24/年 ≫ 预算 1/年）",
          ro["budget_status"] == "OVER" and ro["projected_alerts_per_year"] > 1,
          f"{ro['projected_alerts_per_year']}/年 vs {ro['budget_alerts_per_year']}")
    check("超预算给的是「审 token 放置」而不是「关告警」",
          any("审 token 放置" in a for a in ro["advice"]), ro["advice"][0] if ro["advice"] else "")

    calm = al.NoiseBudget(canaries=14)
    for i in range(40):
        calm.noise(f"bg {i}", ts=now - i * 86400 * 0.9)
    rc = calm.report(now)
    check("零告警 + 噪声贴基线 → OK", rc["budget_status"] == "OK",
          f"noise/day={rc['noise_per_day']} baseline={rc['baseline_noise_per_day']}")

    spike = al.NoiseBudget(canaries=14, baseline_noise_per_day=2.0)
    for i in range(200):
        spike.noise(f"burst {i}", ts=now - (i % 5) * 86400 - 60)
    rs = spike.report(now)
    check("噪声尖峰 → 判为蜜标位置可能已被索引",
          rs["baseline_deviation"] > 3 and any("已被索引" in a for a in rs["advice"]),
          f"deviation={rs['baseline_deviation']}×")

    empty = al.NoiseBudget(canaries=14).report(now)
    check("零流量 → 报放置问题（不是「一切正常」）",
          any("零流量" in a for a in empty["advice"]), empty["advice"][-1] if empty["advice"] else "")

    short = al.NoiseBudget(canaries=14)
    short.alert("x")
    rs2 = short.report(now + 3600)
    check("窗口不足 7 天 → 标 INSUFFICIENT-DATA，不硬给结论",
          rs2["budget_status"] == "INSUFFICIENT-DATA" and not rs2["reliable"],
          f"elapsed={rs2['elapsed_days']}天")

    ob = al.NoiseBudget(alerts_per_year=1, canaries=14)
    for t in ("t1", "t2"):
        ob.alert(t)
    line = ob.budget_line()
    check("超预算时 budget_line 给「本窗口告警/预算上限」+ 运营动作",
          "本窗口告警 2" in line and "预算上限" in line
          and "审 token 放置" in line and "不要关告警" in line,
          line.splitlines()[-1][:70])

    # ---------------------------------------------------------------
    print("\n=== 5. 配置入口：YAML / JSON / 内置子集 ===")
    cfgd = tempfile.mkdtemp(prefix="ukiyo-cfg-")
    yml_path = os.path.join(cfgd, "allow.yaml")
    yml_text = """version: 1
bind_ip: 127.0.0.1
rules:
  - cidr: 203.0.113.0/24
    kind: scanner
    note: 办公网漏扫出口 Nessus
    expires: 2026-12-31
  - cidr: 198.51.100.7
    kind: monitor
    note: Prometheus 探针
    ports: [443, 8080]
  - cidr: 2001:db8:1:2::/64
    kind: backup
    note: v6 夜备
noise_budget:
  canaries: 14
  alerts_per_year: 4
  baseline_noise_per_day: 1.5
  window_days: 30
"""
    with open(yml_path, "w", encoding="utf-8") as f:
        f.write(yml_text)
    b = alc.load(yml_path, bind_ip="127.0.0.1")
    check("YAML 加载：3 条规则", len(b.allowlist) == 3, f"parser={b.parser}")
    check("YAML 加载：类目/端口/过期时间都进来了",
          b.allowlist.rules[0].kind == "scanner"
          and b.allowlist.rules[1].ports == (443, 8080)
          and b.allowlist.rules[0].expires_iso() == "2026-12-31T23:59:59",
          f"expires={b.allowlist.rules[0].expires_iso()}")
    check("YAML 加载：noise_budget 生效",
          b.budget.canaries == 14 and b.budget.alerts_per_year == 4.0
          and b.budget.baseline_noise_per_day == 1.5,
          f"{b.budget.canaries}/{b.budget.alerts_per_year}/{b.budget.baseline_noise_per_day}")
    check("加载后规则可直接用于判定", b.allowlist.check("203.0.113.9", port=443).allowed)

    # JSON 走同一条构建路径
    json_path = os.path.join(cfgd, "allow.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(alc.parse_yaml_subset(yml_text), f, ensure_ascii=False)
    bj = alc.load(json_path, bind_ip="127.0.0.1")
    check("JSON 加载结果与 YAML 一致",
          [r.cidr for r in bj.allowlist.rules] == [r.cidr for r in b.allowlist.rules]
          and bj.budget.canaries == b.budget.canaries, f"parser={bj.parser}")

    # 只有一套解析器：同一文件重复加载必须逐字段一致（不同机器/不同入口都一样）
    b2 = alc.load(yml_path, bind_ip="127.0.0.1")
    check("单一解析器（零第三方依赖）：重复加载结果一致",
          "零依赖" in b.parser
          and [r.to_dict() for r in b2.allowlist.rules] == [r.to_dict() for r in b.allowlist.rules],
          b.parser)
    check("子集解析器拒绝 TAB 缩进并说清楚",
          _raises(lambda: alc.parse_yaml_subset("rules:\n\t- cidr: x\n"), alc.ConfigError),
          "TAB 是 YAML 的经典坑")

    # ---------------------------------------------------------------
    print("\n=== 6. 配置校验硬失败：错一条就拒绝启动，并指出是哪一条 ===")

    def cfg_err(text: str) -> str:
        p = os.path.join(cfgd, f"bad-{abs(hash(text)) % 10**8}.yaml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            alc.load(p, bind_ip="127.0.0.1")
        except alc.ConfigError as e:
            return "\n".join(e.errors)
        return ""

    base_rule = "rules:\n  - cidr: {cidr}\n    kind: {kind}\n    note: {note}\n"
    msg = cfg_err("version: 1\n" + base_rule.format(cidr="10.0.0.0/8", kind="scanner", note="全内网"))
    check("/8 被拒且指出 rules[0]", "rules[0]" in msg and "/8" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\nbind_ip: 10.1.2.3\n"
                  + base_rule.format(cidr="10.1.2.0/24", kind="scanner", note="同网段"))
    check("覆盖自身 bind 地址被拒（bind 来自配置文件）",
          "rules[0]" in msg and "监听地址" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\n" + base_rule.format(cidr="not-a-cidr", kind="scanner", note="x"))
    check("非法 CIDR 被拒", "rules[0]" in msg and "无法解析" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\n" + base_rule.format(cidr="203.0.113.0/24", kind="scannr", note="x"))
    check("类目拼错被拒（不是静默当成 unknown）", "类目" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\nrules:\n  - cidr: 203.0.113.0/24\n    kind: scanner\n")
    check("缺 note 被拒", "缺 note" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\nrules:\n  - cidrr: 203.0.113.0/24\n    kind: scanner\n    note: x\n")
    check("键拼错（cidrr）被拒 —— 否则等于规则为零",
          "未知键" in msg and "cidrr" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 99\n" + base_rule.format(cidr="203.0.113.0/24", kind="scanner", note="x"))
    check("version 不认识被拒", "version" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\nruless:\n  - cidr: 203.0.113.0/24\n")
    check("顶层键拼错被拒", "未知键" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = cfg_err("version: 1\n" + base_rule.format(cidr="203.0.113.0/24", kind="scanner", note="x")
                  + "    expires: 明天\n")
    check("过期时间写错被拒", "过期时间" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    check("文件不存在 → 明确报错，不是当成空表",
          _raises(lambda: alc.load(os.path.join(cfgd, "nope.yaml")), alc.ConfigError))
    # 一次报全：多条错规则应该一次列完，而不是改一条跑一次
    multi = cfg_err("version: 1\nrules:\n"
                    "  - cidr: 10.0.0.0/8\n    kind: scanner\n    note: a\n"
                    "  - cidr: 11.0.0.0/8\n    kind: scanner\n    note: b\n")
    check("多条错误一次报全（rules[0] 与 rules[1] 同时出现）",
          "rules[0]" in multi and "rules[1]" in multi,
          f"{len(multi.splitlines())} 行错误")

    # ---------------------------------------------------------------
    print("\n=== 7. CLI 参数合并 ===")
    bcli = alc.load(yml_path, bind_ip="127.0.0.1",
                    cli_specs=["203.0.113.9:scanner",
                               "2001:db8:9:9::/64|monitor|v6 机房出口",
                               "198.51.100.200:crawler:临时排查:2026-12-31"])
    check("文件 3 条 + CLI 3 条 = 6 条", len(bcli.allowlist) == 6, f"{len(bcli.allowlist)} 条")
    check("CLI 规则追加在文件规则之后（先声明先生效）",
          [r.cidr for r in bcli.allowlist.rules[:3]] == [r.cidr for r in b.allowlist.rules],
          str([r.cidr for r in bcli.allowlist.rules]))
    check("CLI 冒号写法：cidr:kind", bcli.allowlist.rules[3].kind == "scanner")
    check("CLI IPv6 竖线写法可用", bcli.allowlist.rules[4].cidr == "2001:db8:9:9::/64")
    check("CLI 第四段是过期时间，第三段是 note",
          bcli.allowlist.rules[5].note == "临时排查"
          and bcli.allowlist.rules[5].expires_iso() == "2026-12-31T23:59:59",
          f"{bcli.allowlist.rules[5].note} / {bcli.allowlist.rules[5].expires_iso()}")
    check("CLI 计数记在 bundle 上", bcli.cli_rules == 3, f"cli_rules={bcli.cli_rules}")
    msg = _errmsg(lambda: alc.load(yml_path, cli_specs=["0.0.0.0/0:scanner"]))
    check("CLI 写 /0 → 硬失败", "--allow-cidr #1" in msg and "/0" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = _errmsg(lambda: alc.load(yml_path, cli_specs=["203.0.113.0/24"]))
    check("CLI 不写类目 → 硬失败", "认不出类目" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")
    msg = _errmsg(lambda: alc.load(yml_path, cli_specs=["203.0.113.0/24:scanner",
                                                        "198.51.100.0/16:backup"]))
    check("CLI 第 2 条非法时指到 #2", "--allow-cidr #2" in msg, msg.splitlines()[0][:80] if msg else "（没报错）")

    # ---------------------------------------------------------------
    print("\n=== 8. 过期时间：到期当场失效 ===")
    ax = al.Allowlist()
    ax.add("203.0.113.0/24", "scanner", "昨天到期", expires=time.time() - 60)
    ax.add("198.51.100.0/24", "monitor", "一小时后到期", expires=time.time() + 3600)
    check("已过期规则不再放行", not ax.check("203.0.113.9").allowed,
          "serve 是长跑进程，只在加载时过滤等于过期时间形同虚设")
    check("未到期规则照常放行", ax.check("198.51.100.9").allowed)
    check("过期命中被单独计数", ax.stats["expired"] >= 1, f"expired={ax.stats['expired']}")
    check("日期型过期按当天 23:59:59 算",
          al.parse_expiry("2026-12-31") == time.mktime((2026, 12, 31, 23, 59, 59, 0, 0, -1)))
    check("过期时间写错 → 报错（不静默当成永不过期）",
          _raises(lambda: al.parse_expiry("下个月"), al.AllowlistError))

    # ---------------------------------------------------------------
    print("\n=== 9. 请求级前置放行：计数可见、零告警 ===")
    al_g = al.Allowlist(bind_ip=None)
    al_g.add("127.0.0.1", "scanner", "自测：本机当办公网漏扫出口")
    hp_g = Honeypot(world=w, http_port=hd._free_port(), ssh_port=None,
                    ledger_path=os.path.join(d, "gate.jsonl"), enable_ssh=False,
                    dns_sink=False, allowlist=al_g)
    hp_g.request_gate = al_g.check
    hp_g.start()
    try:
        got_g = run_chain(hp_g.http_port)
        cli = hd.Client(f"http://127.0.0.1:{hp_g.http_port}", hd.UA_AGENT)
        for p in ("/", "/robots.txt", "/files/../..etc/passwd", "/nope"):
            cli.get(p)
        st = hp_g.allowlist_status()
        check("状态接口：enabled=True（gate 已装）", st["enabled"] is True)
        check("按类目计数（scanner）", st["requests_by_kind"].get("scanner", 0) >= 6,
              f"scanner={st['requests_by_kind'].get('scanner')} total={st['requests_total']}")
        check("计数合计 == 各类目之和",
              st["requests_total"] == sum(st["requests_by_kind"].values()),
              f"{st['requests_total']}")
        check("top_paths 可见（知道放行了哪些路径）", bool(st["top_paths"]),
              str(st["top_paths"][:3]))
        check("放行后账本零 canary 事件",
              not any(e.get("kind") == "canary" for e in hp_g.ledger.events),
              f"canary={sum(1 for e in hp_g.ledger.events if e.get('kind') == 'canary')}")
        check("放行后 vault 零命中（证据不被污染）", not hp_g.vault.hits,
              f"hits={len(hp_g.vault.hits)}")
        check("放行后带外零告警", not hp_g.oob.alerts(), f"{len(hp_g.oob.alerts())}")
        check("http 事件带 allowlisted 标记（回放界面能标出来）",
              any(e.get("allowlisted") == "scanner" for e in hp_g.ledger.events
                  if e.get("kind") == "http"))
        hp_g.flush_allowlist_ledger()
        agg = [e for e in hp_g.ledger.events
               if e.get("kind") == "allowlist" and "n" in e]
        check("聚合落账：请求级 allowlist 事件带 n（不是逐条刷屏）",
              bool(agg) and agg[0].get("n", 0) >= 1 and agg[0].get("ctype") == "scanner",
              f"n={agg[0].get('n') if agg else None} 条={len(agg)}")
        check("对外响应与不放行实例逐位一致（200/200/200）",
              (got_g["canary"], got_g["sts"], got_g["mcp"]) == (ctl["canary"], ctl["sts"], ctl["mcp"]),
              f"gate={got_g['canary']}/{got_g['sts']}/{got_g['mcp']} "
              f"ctl={ctl['canary']}/{ctl['sts']}/{ctl['mcp']}")
        check("被放行的会话不进判定（评分不被扫描器打高）",
              all(s.score == 0 for s in hp_g.sessions.by_id.values()),
              f"cls={[s.cls for s in hp_g.sessions.by_id.values()]} "
              f"score={[s.score for s in hp_g.sessions.by_id.values()]}")

        # 状态接口真的能访问（不是只有个方法）
        sport = hd._free_port()
        httpd = hd._status_server(hp_g, alc.load(yml_path, bind_ip="127.0.0.1"), sport,
                                  {"instance": 0, "t0": time.time()})
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{sport}/status.json", timeout=5) as r:
                body = r.read().decode("utf-8")
            js = json.loads(body)
            check("GET /status.json 返回按类目计数与预算 KPI",
                  js["requests_by_kind"].get("scanner", 0) >= 6
                  and "本窗口告警" in js["budget_line"] and js["enabled"] is True,
                  f"scanner={js['requests_by_kind'].get('scanner')}")
            with urllib.request.urlopen(f"http://127.0.0.1:{sport}/status", timeout=5) as r:
                txt = r.read().decode("utf-8")
            check("GET /status 文本里放行（静音）与噪声/告警分开列",
                  "放行（静音）按类目" in txt and "噪声/告警" in txt and "scanner=" in txt,
                  txt.splitlines()[2][:60])
            with urllib.request.urlopen(f"http://127.0.0.1:{sport}/kpi", timeout=5) as r:
                kpi = r.read().decode("utf-8")
            check("GET /kpi 给出「本窗口告警 / 预算上限」",
                  "本窗口告警" in kpi and "预算上限" in kpi, kpi.splitlines()[0][:60])
        finally:
            httpd.shutdown()
            httpd.server_close()
    finally:
        hp_g.stop()

    # 按类目分开计数（用两个网段的假来源，避开 127.0.0.1 唯一性）
    al_k = al.Allowlist(bind_ip=None)
    al_k.add("203.0.113.0/24", "scanner", "x")
    al_k.add("198.51.100.0/24", "backup", "y")
    hp_k = Honeypot(world=w, http_port=hd._free_port(), ssh_port=None,
                    ledger_path=os.path.join(d, "kinds.jsonl"), enable_ssh=False,
                    dns_sink=False, allowlist=al_k)
    hp_k.request_gate = al_k.check
    for ip in ("203.0.113.5", "203.0.113.6", "198.51.100.9", "192.0.2.1"):
        hp_k.gate_request(ip, 80)
    check("两个类目分别计数",
          hp_k.allow_counts["scanner"] == 2 and hp_k.allow_counts["backup"] == 1,
          json.dumps({k: v for k, v in hp_k.allow_counts.items() if v}))
    check("未命中不计入放行", hp_k.allowlist_status()["requests_total"] == 3)
    check("未装 gate 时行为完全不变（gate_request 返回 None）",
          Honeypot(world=w, http_port=hd._free_port(), ssh_port=None,
                   ledger_path=os.path.join(d, "nogate.jsonl"), enable_ssh=False,
                   dns_sink=False).gate_request("203.0.113.5", 80) is None)

    # ---------------------------------------------------------------
    print("\n=== 10. CLI 层验收 ===")
    r = subprocess.run([sys.executable, os.path.join(HERE, "honey_demo.py"), "serve", "--help"],
                       capture_output=True, text=True)
    for flag in ("--allowlist", "--allow-cidr", "--noise-budget", "--canaries",
                 "--status-port", "--kpi-interval", "--allowlist-dry-run"):
        check(f"serve --help 含 {flag}", flag in r.stdout)
    bad_cli = os.path.join(cfgd, "cli-bad.yaml")
    with open(bad_cli, "w", encoding="utf-8") as f:
        f.write("version: 1\n" + base_rule.format(cidr="10.0.0.0/8", kind="scanner", note="x"))
    r2 = subprocess.run([sys.executable, os.path.join(HERE, "honey_demo.py"), "serve",
                         "--allowlist", bad_cli, "--allowlist-dry-run"],
                        capture_output=True, text=True)
    check("非法配置在 CLI 层硬失败（退出码 2 + 指出 rules[0]）",
          r2.returncode == 2 and "rules[0]" in r2.stderr,
          f"rc={r2.returncode}")
    r3 = subprocess.run([sys.executable, os.path.join(HERE, "honey_demo.py"), "serve",
                         "--allowlist", yml_path, "--allow-cidr", "203.0.113.9:scanner",
                         "--allowlist-dry-run"], capture_output=True, text=True)
    check("合法配置 dry-run 退出 0 并打印规则表",
          r3.returncode == 0 and "配置校验通过" in r3.stdout and "规则 4 条" in r3.stdout,
          f"rc={r3.returncode}")

    ok = all(results)
    print(f"\n{'=' * 62}\n{'PASS' if ok else 'FAIL'}  {sum(results)}/{len(results)} 项通过")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
