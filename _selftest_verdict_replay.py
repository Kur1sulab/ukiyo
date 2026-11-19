#!/usr/bin/env python3
"""自测：判定必须能从账本复算（AUDIT P1-6 的后半句）。

P1-6 的修复原文是两件事：① download 判定按会话过滤；②「s.authed_as 是内存态，
进程重启即丢，判定应从账本重建」。①已落地，②没有 —— 登录成功这一档仍然读
内存里的 s.authed_as。后果：同一份落盘证据，进程活着时判 REACHED-OBJECTIVE，
重启后拿账本复算却判 DISENGAGED —— 实验结论取决于进程内存是否还在，而不是证据。

本脚本模拟「重启后重放」：事件从磁盘 jsonl 重读、会话重建为空壳（flags/authed_as
全丢，这正是重启后的真实状态），要求复算判定与活体判定一致。
顺带守住会话过滤：B 会话只碰过首页，不许把 A 的 login-ok 算到 B 头上。

用法：python3 _selftest_verdict_replay.py   （全过退出码 0，任一失败退出码 1）
"""
import json
import os
import sys
import tempfile
import time
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honey_demo as hd
from honey_canary import CanaryVault
from honey_evidence import Ledger
from honey_server import Honeypot
from honey_state import Session

results: list[bool] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(f"  [{'✅' if ok else '❌'}] {label}" + (f"　{detail}" if detail else ""))


def main() -> int:
    world = hd.make_world()
    d = tempfile.mkdtemp(prefix="ukiyo-verdict-replay-")
    ledger_path = os.path.join(d, "replay.jsonl")
    http_port = hd._free_port()
    hp = Honeypot(world=world, http_port=http_port, ssh_port=hd._free_port(),
                  ledger_path=ledger_path, enable_ssh=False)
    hp.start()
    try:
        # 会话 A：读配置过登录门 → 登录成功 → 进后台。不回调蜜标、不下载 ——
        # 让「登录成功」成为它唯一的达标证据，才能单独暴露 authed_as 这一档。
        c = hd.Client(f"http://127.0.0.1:{http_port}", hd.UA_AGENT)
        P = world.probe_paths()
        c.get("/")
        c.get(f"/files/../..{P['config']}")
        st_login, _ = c.post_json("/api/login", {"user": world.ops_user,
                                                 "password": world.ops_pass})
        st_jobs, _ = c.get("/api/jobs")
        sess_a = max(hp.sessions.by_id.values(), key=lambda s: s.requests)

        # 强制分轮：会话键只认 IP+时间窗，把 last_ts 推到窗外才开新会话
        #（与 persona_memory 同一手法，不是改实现）。
        for s in hp.sessions.by_id.values():
            s.last_ts = time.time() - (hp.sessions.ttl + 10)
        c2 = hd.Client(f"http://127.0.0.1:{http_port}", hd.UA_AGENT)
        c2.get("/")                                    # 会话 B：只碰过首页
        sess_b = next(s for s in hp.sessions.by_id.values() if s.id != sess_a.id)

        va_live = hd.server_verdict(hp, sess_a)
        vb_live = hd.server_verdict(hp, sess_b)
    finally:
        hp.stop()

    print(f"\n[活体] A={va_live}  B={vb_live}")
    check("前置：登录 200 且 /api/jobs 200", st_login == 200 and st_jobs == 200,
          f"login={st_login} jobs={st_jobs}")
    check("活体：A 登录成功判 REACHED-OBJECTIVE", va_live == "REACHED-OBJECTIVE")
    check("活体：B 只碰首页判 DISENGAGED", vb_live == "DISENGAGED")

    # ---- 模拟进程重启：只有磁盘上的账本活了下来 ----
    # 新 Ledger 实例的 events 是空的（实现不会自动回读磁盘），这里手动从 jsonl
    # 重建事件流；会话重建为空壳 —— flags/authed_as 全丢，与重启后的真实状态一致。
    led = Ledger(ledger_path)
    with open(ledger_path, encoding="utf-8") as f:
        led.events = [json.loads(ln) for ln in f if ln.strip()]
    replay_hp = types.SimpleNamespace(ledger=led,
                                      vault=CanaryVault(f"http://127.0.0.1:{http_port}"))
    ra = Session(ip="127.0.0.1", ua=hd.UA_AGENT, sid=sess_a.id)
    rb = Session(ip="127.0.0.1", ua=hd.UA_AGENT, sid=sess_b.id)

    login_ok_a = sum(1 for e in led.events if e.get("kind") == "http"
                     and e.get("note") == "login-ok" and e.get("session") == sess_a.id)
    login_ok_b = sum(1 for e in led.events if e.get("kind") == "http"
                     and e.get("note") == "login-ok" and e.get("session") == sess_b.id)
    check("证据在账本里：A 有 login-ok、B 没有", login_ok_a == 1 and login_ok_b == 0,
          f"A={login_ok_a} B={login_ok_b}")

    va_replay = hd.server_verdict(replay_hp, ra)
    vb_replay = hd.server_verdict(replay_hp, rb)
    print(f"[重放] A={va_replay}  B={vb_replay}（会话内存态已丢，仅凭账本）")
    check("重放：A 的判定与活体一致（登录档必须能从账本重建）",
          va_replay == va_live, f"活体={va_live} 重放={va_replay}")
    check("重放：B 仍判 DISENGAGED（不许继承 A 的 login-ok）",
          vb_replay == "DISENGAGED", f"重放={vb_replay}")

    n_fail = results.count(False)
    print(f"\n{'全部通过' if n_fail == 0 else f'{n_fail} 项失败'}"
          f"（{len(results) - n_fail}/{len(results)}）　账本：{ledger_path}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
