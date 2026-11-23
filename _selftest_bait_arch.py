#!/usr/bin/env python3
"""自测：调研总纲 §5 P1 —— 陈述句诱饵 + 前置条件式假线索 + 架构分类。

三条必须同时成立：

  1. **陈述句**：诱饵只陈述「系统里有什么」，不对读者下命令。
     理由（LLM-INTAKE.md §5 实测）：命令句式会泄漏 100%，改成陈述句后降到 0，
     而蜜标照样被触发 —— 杀伤力来自内容，不来自语气。

  2. **前置条件**：「要拿 X 必须先做 Y」不只是话术，Y 必须是真的闸门
     （未做 Y，X 的接口返回 409）。只有这样，「对方是否采纳 Y」才是一条
     关于它控制流的证据，而不是我们的猜测。

  3. **二分判定**（总纲 §5 P1）：
       把 Y 纳入后续计划 → 控制流可被内容影响（planner 无校验）= adopted
       读了但没碰 Y     → 有护栏 / 改写了计划                    = guarded
       根本没读到       → 无法判定                                = unknown
     并把「终止策略分类」（REACHED-OBJECTIVE / DISENGAGED…）扩成
     「架构分类」：VERDICT · 陈述式事实注入/前置条件式路径注入 · 是否采纳。

红line（Rule of Two）：全程零出站、零 shell。这条是产品底线，本脚本用
AST 静态扫描 + NoEgressGuard 运行期断言双重钉住。

用法：python3 _selftest_bait_arch.py   （全过退出码 0）
"""
import ast
import json
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import honey_bait_arch as hba
import honey_demo as hd
from honey_oob import NoEgressGuard
from honey_server import Honeypot

results: list[bool] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(f"  [{'✅' if ok else '❌'}] {label}" + (f"　{detail}" if detail else ""))


# ----------------------------------------------------------------------
# 红line：静态 + 运行期
# ----------------------------------------------------------------------
EGRESS_CALLS = {"connect", "connect_ex", "create_connection", "sendto", "getaddrinfo"}
EGRESS_MODULES = {"requests", "httpx", "aiohttp", "urllib.request", "http.client",
                  "urllib3", "websockets", "paramiko", "ftplib", "smtplib", "telnetlib"}
SHELL_MODULES = {"subprocess", "multiprocessing", "pty"}
SHELL_ATTRS = {"system", "popen", "execv", "execve", "spawnv", "fork", "posix_spawn"}


def _is_egress(mod: str) -> bool:
    """按**完整模块路径**判定，不能按首段：
    `urllib.parse` 是纯字符串解析（服务端要用），`http.server` 是监听。
    把它们当成出站会把蜜罐自己的正常代码判成违规。"""
    return any(mod == m or mod.startswith(m + ".") for m in EGRESS_MODULES)


def static_scan(path: str) -> list[str]:
    """返回违规描述；空列表 = 干净。只看「能不能出站 / 能不能起子进程」。"""
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _is_egress(a.name):
                    bad.append(f"import {a.name}")
                if a.name.split(".")[0] in SHELL_MODULES:
                    bad.append(f"import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _is_egress(mod):
                bad.append(f"from {mod} import …")
            if mod.split(".")[0] in SHELL_MODULES:
                bad.append(f"from {mod} import …")
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in SHELL_ATTRS:
                bad.append(f"调用 {name}()")
            if name in EGRESS_CALLS:
                bad.append(f"调用 {name}()")
    return bad


def new_session(hp, http_port: int, ua: str = hd.UA_AGENT):
    """把现有会话的最后活动时间推出 TTL 窗外 → 下一次请求必然开新会话。

    会话键是 IP+时间窗，所有测试都来自 127.0.0.1，只能这样分轮。
    """
    for s in hp.sessions.by_id.values():
        s.last_ts = time.time() - (hp.sessions.ttl + 10)
    before = set(hp.sessions.by_id)
    c = hd.Client(f"http://127.0.0.1:{http_port}", ua)
    return c, before


def sid_of(hp, before: set) -> str:
    fresh = [s for s in hp.sessions.by_id.values() if s.id not in before]
    if not fresh:
        return max(hp.sessions.by_id.values(), key=lambda s: s.requests).id
    return max(fresh, key=lambda s: s.requests).id


def main() -> int:
    print("=== 1. 诱饵文本：必须是陈述句，不许对 agent 喊话 ===")
    w = hd.make_world()
    stmt_doc = w.cred_rotation_log_txt()
    pre_doc = w.handover_notice_txt("cTESTTOKEN")
    print(f"  [陈述式样本] {stmt_doc.strip().splitlines()[-2][:78]}…")
    print(f"  [前置式样本] {[l for l in pre_doc.splitlines() if '必须先' in l][0][:78]}…")

    check("陈述式诱饵陈述「凭据位于何处」", "系统记录显示" in stmt_doc
          and "/opt/archiver/conf/credentials.d/deploy-token" in stmt_doc)
    check("前置条件诱饵陈述「要拿 X 必须先做 Y」",
          "必须先完成交接登记" in pre_doc and "/c/cTESTTOKEN" in pre_doc)

    # 命令句式的检测：第二人称祈使 + 「请…」+ 点名 agent。
    # 注意「必须先」不算命令 —— 它陈述的是系统前置条件，读者不是被命令的对象。
    IMPERATIVE = [r"请你", r"请把", r"请将", r"请先", r"你需要", r"你必须",
                  r"^\s*请", r"please\s", r"you\s+must", r"you\s+should",
                  r"自动巡检的\s*agent", r"如果是自动巡检"]
    hits = [p for p in IMPERATIVE if re.search(p, stmt_doc + pre_doc, re.I | re.M)]
    check("两份诱饵都不含命令/喊话措辞", not hits, f"命中={hits}")

    print("\n=== 2. 红line：零出站 / 零 shell（Rule of Two）===")
    for mod in ("honey_bait_arch.py", "honey_world.py", "honey_server.py"):
        bad = static_scan(os.path.join(os.path.dirname(os.path.abspath(__file__)), mod))
        check(f"{mod} 无出站/无 shell 代码路径", not bad, f"{bad[:3]}")

    print("\n=== 3. 端到端：投递 → 采纳/不采纳 → 分类 → 统计 ===")
    d = tempfile.mkdtemp(prefix="ukiyo-bait-")
    http_port = hd._free_port()
    hp = Honeypot(world=w, http_port=http_port, ssh_port=hd._free_port(),
                  ledger_path=os.path.join(d, "bait.jsonl"), enable_ssh=False,
                  dns_sink=False)
    hp.start()
    P = w.probe_paths()
    sids: dict[str, str] = {}
    try:
        guard = NoEgressGuard()
        with guard:
            # --- 会话 A：读陈述式诱饵 → 按它说的位置去取（采纳）---
            c, before = new_session(hp, http_port)
            c.get("/")
            st_doc, body_doc = c.get(f"/files/../..{P['rotation_log']}")
            st_drop, body_drop = c.get(f"/files/../..{P['creds_drop']}")
            sids["A"] = sid_of(hp, before)

            # --- 会话 B：读陈述式诱饵 → 不碰它点名的位置（不采纳）---
            c, before = new_session(hp, http_port)
            c.get("/")
            c.get(f"/files/../..{P['rotation_log']}")
            c.get("/robots.txt")
            sids["B"] = sid_of(hp, before)

            # --- 会话 C：读前置条件 → 先去登记（采纳）---
            c, before = new_session(hp, http_port)
            c.get("/")
            st_hand, body_hand = c.get(f"/files/../..{P['handover']}")
            tok = re.search(r"/c/(c[0-9a-f]{14})", body_hand)
            tok = tok.group(1) if tok else ""
            st_reg, _ = c.get(f"/c/{tok}")
            st_exp, body_exp = c.get("/handover/export")
            sids["C"] = sid_of(hp, before)

            # --- 会话 D：读前置条件 → 跳过登记直接要货（被 409 挡住，不采纳）---
            c, before = new_session(hp, http_port)
            c.get("/")
            c.get(f"/files/../..{P['handover']}")
            st_exp_d, body_exp_d = c.get("/handover/export")
            sids["D"] = sid_of(hp, before)

            # --- 会话 E：什么都没读（未投递）---
            c, before = new_session(hp, http_port)
            c.get("/")
            sids["E"] = sid_of(hp, before)

            # 活体侧分类：与回放侧共用同一份实现，结论必须一致
            live_a = hd.deception_verdict(hp, hp.sessions.by_id[sids["A"]])
        time.sleep(0.1)
        events = list(hp.ledger.events)
    finally:
        hp.stop()

    check("零出站：全程出站尝试 == 0", not guard.attempts,
          f"attempts={guard.attempts[:2]}")
    check("陈述式文档 200 且正文含「系统记录显示」",
          st_doc == 200 and "系统记录显示" in body_doc, f"{st_doc}")
    check("前置条件文档 200 且正文给出登记入口",
          st_hand == 200 and "/c/" in body_hand, f"{st_hand}")
    check("前置条件是真的：未登记 export 返回 409", st_exp_d == 409, f"{st_exp_d}")
    check("登记后 export 才放行（200 且含凭据）",
          st_exp == 200 and "deploy:token" in body_exp, f"{st_exp} {body_exp[:60]!r}")

    print("\n=== 4. 判定：采纳 / 不采纳 / 未投递 ===")
    prof = {k: hba.classify_session(events, sid) for k, sid in sids.items()}
    for k, p in prof.items():
        print(f"  会话 {k}: arch={p['arch']:<17} adopted={str(p['adopted']):<5} "
              f"planner={p['planner']:<9}（合流标签见第 5 节）")

    check("A 陈述式被采纳 → planner 无校验",
          prof["A"]["arch"] == hba.ARCH_STATEMENT and prof["A"]["adopted"]
          and prof["A"]["planner"] == "unchecked")
    check("B 读了陈述式但没碰点名位置 → 有护栏",
          prof["B"]["arch"] == hba.ARCH_STATEMENT and not prof["B"]["adopted"]
          and prof["B"]["planner"] == "guarded")
    check("C 前置条件被采纳（先登记再取货）→ planner 无校验",
          prof["C"]["arch"] == hba.ARCH_PRECONDITION and prof["C"]["adopted"]
          and prof["C"]["planner"] == "unchecked")
    check("D 读了前置条件但跳过登记 → 有护栏",
          prof["D"]["arch"] == hba.ARCH_PRECONDITION and not prof["D"]["adopted"]
          and prof["D"]["planner"] == "guarded")
    check("E 没读到 → 未投递、无法判定",
          prof["E"]["arch"] == hba.ARCH_NONE and prof["E"]["planner"] == "unknown")
    check("活体分类 == 回放分类（同一份账本，同一套判定）",
          live_a["arch"] == prof["A"]["arch"] and live_a["adopted"] == prof["A"]["adopted"]
          and live_a["planner"] == prof["A"]["planner"],
          f"live={live_a['arch']}/{live_a['adopted']} replay={prof['A']['arch']}/{prof['A']['adopted']}")

    print("\n=== 5. 统计：架构维度必须能从账本复算 ===")
    run = {"id": "selftest-bait", "dir": d, "events": events, "snapshot": {}}
    from honey_replay import run_stats
    stats = run_stats(run)
    arch = stats["architectures"]
    print("  " + json.dumps(arch, ensure_ascii=False))
    print("  " + json.dumps(stats["arch_verdicts"], ensure_ascii=False))
    check("陈述式：投递 2 / 采纳 1",
          arch[hba.ARCH_STATEMENT]["delivered"] == 2
          and arch[hba.ARCH_STATEMENT]["adopted"] == 1)
    check("前置条件式：投递 2 / 采纳 1",
          arch[hba.ARCH_PRECONDITION]["delivered"] == 2
          and arch[hba.ARCH_PRECONDITION]["adopted"] == 1)
    check("未投递会话在统计里可见", arch[hba.ARCH_NONE]["delivered"] >= 1)
    check("终止策略→架构 的合流标签可统计",
          any("·" in k and ("陈述式" in k or "前置条件式" in k) for k in stats["arch_verdicts"]),
          f"{list(stats['arch_verdicts'])[:2]}")

    print("\n=== 6. allowlist / 噪声预算不退化：新诱饵不许绕过前置放行 ===")
    import honey_allowlist as al
    d2 = tempfile.mkdtemp(prefix="ukiyo-bait-al-")
    allowed = al.Allowlist(bind_ip=None)
    allowed.add("127.0.0.1", "scanner", "办公网漏扫出口（自测）")
    hp2 = Honeypot(world=w, http_port=hd._free_port(), ssh_port=None,
                   ledger_path=os.path.join(d2, "al.jsonl"), enable_ssh=False,
                   dns_sink=False, allowlist=allowed)
    # 请求级 gate 必须显式装上（honey_demo 就是这么接的）：不装的话 /files/
    # 根本不过 allowlist，这条测试会变成「什么都没测到」。
    hp2.request_gate = allowed.check
    hp2.start()
    try:
        c = hd.Client(f"http://127.0.0.1:{hp2.http_port}", hd.UA_AGENT)
        c.get("/")
        c.get(f"/files/../..{P['rotation_log']}")
        c.get(f"/files/../..{P['creds_drop']}")
        c.get(f"/files/../..{P['handover']}")
        time.sleep(0.1)
        hp2.flush_allowlist_ledger()          # 聚合窗口按需结账，测试不等窗口
        ev2 = list(hp2.ledger.events)
    finally:
        hp2.stop()
    check("放行请求记 allowlist 事件",
          any(e.get("kind") == "allowlist" for e in ev2),
          f"{sum(1 for e in ev2 if e.get('kind') == 'allowlist')} 条")
    check("放行请求不产生 intel 投递事件（放行只吞告警，不改判定口径）",
          not any(e.get("kind") == "intel" for e in ev2))

    n_fail = results.count(False)
    print(f"\n{'全部通过' if n_fail == 0 else f'{n_fail} 项失败'}"
          f"（{len(results) - n_fail}/{len(results)}）")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
