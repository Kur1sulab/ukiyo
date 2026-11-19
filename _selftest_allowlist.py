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

用法：python3 _selftest_allowlist.py   （全过退出码 0，任一失败退出码 1）
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honey_allowlist as al
import honey_demo as hd
import honey_state
from honey_server import Honeypot
from _selftest_oob import http_post, sign_v4      # 复用独立签名器，避免第三份实现漂移

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

    ok = all(results)
    print(f"\n{'=' * 62}\n{'PASS' if ok else 'FAIL'}  {sum(results)}/{len(results)} 项通过")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
