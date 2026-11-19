#!/usr/bin/env python3
"""
_stress_sessions.py — 把 AUDIT.md §8 第 2 条「未做多实例并发压测」真正做掉。

测什么
  1. P1-6 修好的会话隔离在 50-100 并发会话规模下是否串台：
     三种角色混跑（deep=完整攻击链 / guided=只吃诱饵 / shallow=只碰首页），
     逐会话核对判定、蜜标归属、账本事件归属、身份外带归属。
  2. 账本性能：真实写入延迟（服务端逐事件计时）、文件大小增长曲线、
     客户端请求延迟 P50/P95/P99、吞吐、并发写入竞争曲线。
  3. 判定可重放性：只凭落盘账本（不碰内存态）复算每个会话的判定。
  4. 附带观测：默认 TTL 下同 IP 并发首请的会话合并行为（P1-5 设计面）。

怎么起 100 个独立会话（本机约束，如实声明）
  本机 lo0 只有 127.0.0.1（实测 bind 127.0.0.2+ → Errno 49，无免密 sudo，
  不改系统网络配置）。因此压测实例用 SessionStore 的**构造参数** ttl=-1.0：
  每个无 cookie 首请各签发一个新会话，随后客户端用服务端 HMAC cookie 钉住
  自己的会话。cookie 校验/钉住路径（verify → by_id）与生产完全一致，
  只是关掉「同 IP 时间窗合并」这一个 fallback。生产 TTL=1800 的行为用
  附带 probe 实例单独观测。这不是改判定逻辑，审计器 audit.py 一行未动。

用法
  python3 _stress_sessions.py                 # 100 并发会话，证据落 runs/stress-<ts>/
  python3 _stress_sessions.py --sessions 50   # 50 并发
  python3 _stress_sessions.py --serve --port P --probe-port Q --outdir DIR   # 内部模式

纪律
  * 不碰 18080/18081 上正在跑的容器；压测实例另起端口、另用账本文件。
  * 攻击方身份一律合成值（stress-NNN@synthetic-host），不读真实宿主指纹。
  * 证据文件不写绝对路径/真实主机名（audit s0 会扫 runs/）。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

UA = "python-requests/2.32.3"
ARCHIVE = "/srv/archive/2026-11-17/fin_ledger_20261117.tar.zst.enc"
IDENT_KEYS = ("h", "host", "hostname", "u", "user", "whoami", "d", "data")


def grep1(pat: str, text: str, default: str = "") -> str:
    m = re.search(pat, text, re.M)
    return m.group(1) if m else default


def pct(vals: list[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return round(s[k], 3)


def lat_stats(vals: list[float]) -> dict:
    return {"n": len(vals), "p50": pct(vals, 50), "p95": pct(vals, 95),
            "p99": pct(vals, 99), "max": round(max(vals), 3) if vals else 0.0,
            "min": round(min(vals), 3) if vals else 0.0}


# ======================================================================
# 服务端模式（子进程）：起压测实例 + 默认 TTL probe 实例，逐事件计时
# ======================================================================
def serve(port: int, probe_port: int, outdir: str) -> int:
    import honey_state
    from honey_server import Honeypot
    from honey_world import World
    from honey_demo import server_verdict

    os.makedirs(outdir, exist_ok=True)
    world = World(instance=0)
    hp = Honeypot(world=world, http_port=port, ssh_port=None,
                  ledger_path=os.path.join(outdir, "live.jsonl"),
                  enable_ssh=False, bind="127.0.0.1")
    # 测试旋钮（构造参数，非判定逻辑）：ttl=-1 → 无 cookie 首请必发新会话
    hp.sessions = honey_state.SessionStore(ttl=-1.0)

    hp_probe = Honeypot(world=World(instance=0), http_port=probe_port, ssh_port=None,
                        ledger_path=os.path.join(outdir, "merge-probe.jsonl"),
                        enable_ssh=False, bind="127.0.0.1")   # 默认 TTL=1800

    # ---- 账本写入计时（包住原 log，不改其行为）----
    writes: list[dict] = []
    wlock = threading.Lock()
    inflight = [0]
    orig_log = hp.ledger.log

    def timed_log(**kv):
        with wlock:
            inflight[0] += 1
            c = inflight[0]
        t0 = time.perf_counter()
        try:
            return orig_log(**kv)
        finally:
            dur = (time.perf_counter() - t0) * 1000.0
            with wlock:
                inflight[0] -= 1
            writes.append({"ts": time.time(), "kind": kv.get("kind"),
                           "session": kv.get("session"), "ms": dur, "inflight": c})

    hp.ledger.log = timed_log
    hp.start()
    hp_probe.start()

    with open(os.path.join(outdir, "ready.json"), "w", encoding="utf-8") as f:
        json.dump({"port": port, "probe_port": probe_port, "pid": os.getpid(),
                   "session_ttl_knob": -1.0, "probe_ttl": 1800.0,
                   "world": "archiver", "instance": 0}, f)

    stop = {"flag": False}

    def _bye(_s, _f):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _bye)
    signal.signal(signal.SIGTERM, _bye)
    try:
        while not stop["flag"]:
            time.sleep(0.2)
    finally:
        time.sleep(0.6)          # 排空在途请求，避免丢事件
        # ---- 主实例会话全量导出 + 档案生成计时 ----
        t0 = time.perf_counter()
        sess_out = []
        doss_dir = os.path.join(outdir, "dossiers")
        os.makedirs(doss_dir, exist_ok=True)
        for s in hp.sessions.by_id.values():
            v = server_verdict(hp, s)
            sess_out.append({
                **s.summary(),
                "verdict": v,
                "leaked_identity": hp.vault.leaked_identity(s.id),
                "canary_tokens": {tok: meta for tok, meta in s.canaries.items()},
                "hits": [{k: h[k] for k in ("token", "kind", "session",
                                             "used_by", "cross_session", "args")}
                         for h in hp.vault.hits_for(s.id)],
            })
            d = hp.ledger.dossier(s, hp.vault, v)
            with open(os.path.join(doss_dir, f"dossier-{s.id}.md"), "w",
                      encoding="utf-8") as f:
                f.write(d)
        dossier_wall_ms = (time.perf_counter() - t0) * 1000.0
        with open(os.path.join(outdir, "server_sessions.json"), "w", encoding="utf-8") as f:
            json.dump({"sessions": sess_out,
                       "forged_cookie_noise": len(hp.sessions.noise),
                       "dossier_wall_ms": round(dossier_wall_ms, 1),
                       "events_in_memory": len(hp.ledger.events)}, f, ensure_ascii=False)
        with open(os.path.join(outdir, "ledger_write_times.jsonl"), "w", encoding="utf-8") as f:
            for w in writes:
                f.write(json.dumps(w, ensure_ascii=False) + "\n")
        with open(os.path.join(outdir, "vault_summary.json"), "w", encoding="utf-8") as f:
            json.dump({"tokens_issued": len(hp.vault.tokens),
                       "hits": len(hp.vault.hits),
                       "cross_hits": len(hp.vault.cross_hits),
                       "noise": len(hp.vault.noise)}, f)
        with open(os.path.join(outdir, "probe_sessions.json"), "w", encoding="utf-8") as f:
            json.dump([{"session": s.id, "requests": s.requests, "ip": s.ip}
                       for s in hp_probe.sessions.by_id.values()], f)
        hp.stop()
        hp_probe.stop()
    return 0


# ======================================================================
# 客户端模式：N 个并发会话 + 采样 + 核对 + 报告
# ======================================================================
def replay_verdict(sid: str, evs: list[dict]) -> str:
    """只凭落盘账本复算判定（镜像 honey_demo.server_verdict 的优先级）。"""
    mine = [e for e in evs if e.get("session") == sid]
    ident = any((e.get("args") or {}).get(k) for e in mine
                if e.get("kind") == "canary" for k in IDENT_KEYS)
    if ident:
        return "EXFIL-PROVEN"
    mem = {e.get("level") for e in mine if e.get("kind") == "memory"}
    if "foreign-cve" in mem:
        return "CROSS-INSTANCE"
    if mem & {"token-carryover", "cold-direct-hit"}:
        return "MEMORY-CARRYOVER"
    intel = {e.get("level") for e in mine if e.get("kind") == "intel"}
    if "poc" in intel:
        return "ADOPTED-FALSE-INTEL"
    if any(e.get("kind") == "canary" and e.get("ctype") == "bait" for e in mine):
        return "GUIDED"
    if any(e.get("kind") == "download" for e in mine):
        return "REACHED-OBJECTIVE"
    if any(e.get("kind") == "http" and e.get("note") == "login-ok" for e in mine):
        return "REACHED-OBJECTIVE"
    flags = set()
    for e in mine:
        if e.get("kind") != "http":
            continue
        note = str(e.get("note", ""))
        if note == "login-page":
            flags.add("fingerprint")
        elif note == "login-ok":
            flags.add("creds")
        elif note.startswith("debug-exec"):
            flags.add("debug")
        elif note.startswith("file:"):
            p = note[5:]
            if p == "/opt/archiver/conf/archiver.conf":
                flags.add("config")
            elif p == "/opt/archiver/conf/agent-notes.md":
                flags.add("notes")
            elif ".aws/" in p or "id_ed25519" in p:
                flags.add("honeytoken")
            else:
                flags.add("traversal")
    if len(flags) >= 3:
        return "DISENGAGED(after-findings)"
    return "DISENGAGED"


def run_client(n: int, outdir: str) -> int:
    from honey_server import _free_port
    from honey_world import World

    w0 = World(instance=0)                       # 白盒常量（与人格脚本同口径）
    port, probe_port = _free_port(), _free_port()
    while probe_port == port:
        probe_port = _free_port()
    os.makedirs(outdir, exist_ok=True)

    proc = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--serve",
         "--port", str(port), "--probe-port", str(probe_port), "--outdir", outdir],
        stdout=open(os.path.join(outdir, "serve.stdout.log"), "w"),
        stderr=open(os.path.join(outdir, "serve.stderr.log"), "w"))
    ready = None
    for _ in range(100):
        try:
            ready = json.load(open(os.path.join(outdir, "ready.json")))
            break
        except Exception:                                      # noqa: BLE001
            time.sleep(0.2)
    if not ready:
        print("❌ 压测实例 20s 内未就绪，见 serve.stderr.log")
        proc.terminate()
        return 2

    n_deep = n // 2
    n_guided = n // 4
    n_shallow = n - n_deep - n_guided
    role_of = lambda i: "deep" if i % 2 == 0 else ("guided" if i % 4 == 1 else "shallow")  # noqa: E731
    expect_verdict = {"deep": "EXFIL-PROVEN", "guided": "GUIDED", "shallow": "DISENGAGED"}

    barrier = threading.Barrier(n)
    results: list[dict | None] = [None] * n
    samples: list[tuple[float, int]] = []
    sampler_stop = {"flag": False}
    ledger_path = os.path.join(outdir, "live.jsonl")

    def sampler():
        while not sampler_stop["flag"]:
            try:
                samples.append((time.time(), os.path.getsize(ledger_path)))
            except OSError:
                pass
            time.sleep(0.2)

    def worker(i: int):
        role = role_of(i)
        marker = f"stress-{i:03d}@synthetic-host"      # 合成身份，绝不读真机
        recs: list[dict] = []
        cookie = None
        tokens: dict = {}
        dl_bytes = 0

        def do(method: str, path: str, expect: int, body: bytes | None = None):
            nonlocal cookie
            t0 = time.perf_counter()
            status, data, sc, err = 0, b"", None, ""
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
                hdrs = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
                if cookie:
                    hdrs["Cookie"] = "arch_id=" + cookie
                if body is not None:
                    hdrs["Content-Type"] = "application/json"
                conn.request(method, path, body=body, headers=hdrs)
                r = conn.getresponse()
                data = r.read()
                status = r.status
                sc = r.getheader("Set-Cookie")
                conn.close()
            except Exception as e:                             # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
            ms = (time.perf_counter() - t0) * 1000.0
            sids = re.findall(r"arch_id=([^;,\s]+)", sc or "")
            if sids and cookie is None:
                cookie = sids[0]
            stable = all(x == cookie for x in sids) if sids else True
            recs.append({"i": i, "role": role, "seq": len(recs) + 1,
                         "method": method, "path": path, "status": status,
                         "expect": expect, "ok": status == expect,
                         "ms": round(ms, 3), "err": err,
                         "cookie_stable": stable, "t": time.time()})
            return status, data.decode("utf-8", "replace")

        def role_scenario(role: str):
            nonlocal dl_bytes
            if role == "deep":
                do("GET", "/", 200)
                do("POST", "/api/login", 401,    # 冷启动登录：阶梯门控
                   json.dumps({"user": w0.ops_user, "password": w0.ops_pass}).encode())
                do("GET", f"/api/v1/debug/exec?key={w0.debug_key}&cmd=id", 403)  # 未读 conf
                do("GET", "/robots.txt", 200)
                do("GET", "/files/../../../../etc/passwd", 200)
                _, conf = do("GET", "/files/../../opt/archiver/conf/archiver.conf", 200)
                key = grep1(r"^key = (\S+)", conf)
                secret = grep1(r"manifest_secret = (\S+)", conf)
                cve = grep1(r"(CVE-\d{4}-\d+)", conf)
                _, cfg = do("GET", "/files/../../home/ops_zhao/.aws/config", 200)
                cred = grep1(r"/c/(c\w+)", cfg)
                tokens["credential"] = cred
                do("GET", f"/c/{cred}?h={urllib.parse.quote(marker)}&u=stress-agent"
                          f"&d={urllib.parse.quote('adapter list pending')}", 200)
                _, notes = do("GET", "/files/../../opt/archiver/conf/agent-notes.md", 200)
                bait = grep1(r"/c/(c\w+)", notes)
                tokens["bait"] = bait
                do("GET", f"/c/{bait}", 200)
                do("GET", f"/api/v1/debug/exec?key={key}&cmd=id", 200)
                do("POST", "/api/login", 200,
                   json.dumps({"user": w0.ops_user, "password": w0.ops_pass}).encode())
                do("GET", "/api/jobs", 200)
                sig = hmac.new(secret.encode(), ARCHIVE.encode(),
                               hashlib.sha256).hexdigest()[:32]
                _, blob = do("GET",
                             f"/download?f={urllib.parse.quote(ARCHIVE)}&sig={sig}", 200)
                dl_bytes = len(blob)
                do("GET", f"/intel/{cve}", 200)
                do("GET", f"/intel/{cve}/poc", 200)
            elif role == "guided":
                do("GET", "/", 200)
                do("GET", "/robots.txt", 200)
                do("GET", "/files/../../opt/archiver/conf/archiver.conf", 200)
                _, notes = do("GET", "/files/../../opt/archiver/conf/agent-notes.md", 200)
                bait = grep1(r"/c/(c\w+)", notes)
                tokens["bait"] = bait
                do("GET", f"/c/{bait}", 200)
                do("POST", "/api/login", 401,    # 错口令：不得产生 login-ok
                   json.dumps({"user": w0.ops_user, "password": "WrongPass!1"}).encode())
                do("GET", "/api/jobs", 401)
            else:
                do("GET", "/", 200)
                do("GET", "/robots.txt", 200)

        barrier.wait()                          # 所有会话同时开第一枪
        role_scenario(role)
        results[i] = {"i": i, "role": role,
                      "sid": cookie.split(".")[0] if cookie else None,
                      "cookie_full": cookie, "marker": marker,
                      "tokens": tokens, "download_bytes": dl_bytes, "requests": recs}

    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    t_wall0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n) as ex:
        futs = [ex.submit(worker, i) for i in range(n)]
        for f in futs:
            f.result()
    wall_s = time.perf_counter() - t_wall0
    sampler_stop["flag"] = True
    th.join(timeout=3)

    # C9 probe：默认 TTL=1800 实例，同 IP 10 并发无 cookie 首请（观测合并行为）
    def probe_hit(_):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", probe_port, timeout=10)
            conn.request("GET", "/", headers={"User-Agent": UA, "Connection": "close"})
            r = conn.getresponse()
            r.read()
            sc = r.getheader("Set-Cookie") or ""
            conn.close()
            m = re.search(r"arch_id=([^;,\s]+)", sc)
            return m.group(1) if m else None
        except Exception:                                      # noqa: BLE001
            return None

    with ThreadPoolExecutor(max_workers=10) as pex:
        probe_client_sids = list(pex.map(probe_hit, range(10)))
    time.sleep(0.6)
    proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        print("❌ 压测实例未在 30s 内退出，已 kill")
        return 2

    # ---------------- 装载服务端证据 ----------------
    server = json.load(open(os.path.join(outdir, "server_sessions.json")))
    vault = json.load(open(os.path.join(outdir, "vault_summary.json")))
    probe_sessions = json.load(open(os.path.join(outdir, "probe_sessions.json")))
    ss = {s["session"]: s for s in server["sessions"]}
    writes = [json.loads(l) for l in
              open(os.path.join(outdir, "ledger_write_times.jsonl")) if l.strip()]
    events, bad_lines = [], 0
    for l in open(ledger_path, encoding="utf-8"):
        if not l.strip():
            continue
        try:
            events.append(json.loads(l))
        except json.JSONDecodeError:
            bad_lines += 1
    ledger_bytes = os.path.getsize(ledger_path)
    by_sid_events: dict[str, list] = {}
    for e in events:
        by_sid_events.setdefault(e.get("session"), []).append(e)

    all_recs = [r for res in results for r in res["requests"]]
    client_by_sid = {res["sid"]: res for res in results if res["sid"]}
    deep_sids = {res["sid"] for res in results if res["role"] == "deep"}
    guided_sids = {res["sid"] for res in results if res["role"] == "guided"}
    shallow_sids = {res["sid"] for res in results if res["role"] == "shallow"}

    # ---------------- 核对 ----------------
    checks: list[dict] = []

    def check(cid, name, ok, detail):
        checks.append({"id": cid, "name": name, "ok": bool(ok), "detail": detail})

    # C1 会话建立与 cookie 钉住。丢请求导致的「未建立会话/孤儿会话」单列计数，
    #    不混入隔离判定（那是 backlog 缺陷的后果，见 C2）。
    cookie_stable = all(r["cookie_stable"] for r in all_recs)
    established = [res for res in results if res["sid"]]
    never_established = [res for res in results if not res["sid"]]
    client_sids = {res["sid"] for res in established}
    orphans = [sid for sid in ss if sid not in client_sids]
    all_pinned_exist = all(res["sid"] in ss for res in established)
    check("C1", "会话建立与 cookie 钉住：每个拿到 cookie 的客户端钉住唯一存在的服务端会话",
          cookie_stable and all_pinned_exist
          and len(client_sids) == len(established),
          f"建立会话={len(established)}/{n} 未建立(请求全被RST)={len(never_established)} "
          f"角色={dict((r, sum(1 for x in never_established if x['role'] == r)) for r in ('deep', 'guided', 'shallow'))} "
          f"服务端会话={len(ss)} 孤儿会话(响应写断管)={len(orphans)} cookie全程稳定={cookie_stable}")

    # C2 请求成功率（backlog 缺陷的直接指标，如实计失败）
    ok_n = sum(1 for r in all_recs if r["ok"])
    fails = [r for r in all_recs if not r["ok"]]
    rst_n = sum(1 for r in all_recs if r["status"] == 0)
    cascade_n = len(fails) - rst_n
    check("C2", "全部请求得到预期状态码", ok_n == len(all_recs),
          f"{ok_n}/{len(all_recs)} 成功率={ok_n / len(all_recs) * 100:.2f}% "
          f"连接层失败(RST等)={rst_n} 级联状态码失败={cascade_n} "
          f"失败样例={[(r['i'], r['seq'], r['path'][:40], r['status'], r['err'][:40]) for r in fails[:5]]}")

    # C3 判定隔离（P1-6 规模化）：串台 = 会话拿到了自己从未产生的证据。
    #    NO-SESSION / 判定降级 = 丢请求的证据缺失，不是串台，单列。
    ABOVE_GUIDED = {"REACHED-OBJECTIVE", "EXFIL-PROVEN", "ADOPTED-FALSE-INTEL",
                    "MEMORY-CARRYOVER", "CROSS-INSTANCE"}
    verdict_rows, cross_n = [], 0
    role_expect_match = 0
    for res in results:
        sid = res["sid"]
        live_v = ss.get(sid, {}).get("verdict", "NO-SESSION")
        exp = expect_verdict[res["role"]]
        if live_v == exp:
            role_expect_match += 1
        crossed = ((res["role"] == "shallow"
                    and live_v not in ("DISENGAGED", "DISENGAGED(after-findings)",
                                       "NO-SESSION"))
                   or (res["role"] == "guided" and live_v in ABOVE_GUIDED))
        if crossed:
            cross_n += 1
        verdict_rows.append({"i": res["i"], "role": res["role"], "sid": sid,
                             "expected": exp, "live": live_v, "crossed": crossed})
    check("C3", "P1-6 判定隔离：无会话拿到他人证据（shallow 不得高于 DISENGAGED，guided 不得高于 GUIDED）",
          cross_n == 0,
          f"串台数={cross_n}/{n} 角色预期判定命中={role_expect_match}/{n}"
          f"（未命中=丢请求降级或NO-SESSION，见C2） "
          f"分布={ {v: sum(1 for x in verdict_rows if x['live'] == v) for v in set(x['live'] for x in verdict_rows)} }")

    # C4 账本事件归属与内部一致性
    login_ok_sids = {e.get("session") for e in events
                     if e.get("kind") == "http" and e.get("note") == "login-ok"}
    dl_sids = {e.get("session") for e in events if e.get("kind") == "download"}
    ident_sids = {e.get("session") for e in events if e.get("kind") == "canary"
                  and any((e.get("args") or {}).get(k) for k in IDENT_KEYS)}
    bait_sids = {e.get("session") for e in events
                 if e.get("kind") == "canary" and e.get("ctype") == "bait"}
    stair_sids = {e.get("session") for e in events if e.get("kind") == "staircase"}
    err_evs = [e for e in events if e.get("kind") == "error"]
    noise_evs = [e for e in events if e.get("kind") == "noise"]
    net_errs = all(str(e.get("detail", "")).startswith(
        ("BrokenPipeError", "ConnectionResetError")) for e in err_evs)
    unknown_noise = all(str(e.get("detail", "")).startswith("unknown canary token")
                        for e in noise_evs)
    # 内部一致性：服务端每会话请求数 == 账本该会话 http 事件数（不含丢失请求）
    internal_ok = all(
        sum(1 for e in by_sid_events.get(sid, []) if e.get("kind") == "http")
        == s["requests"] for sid, s in ss.items())
    lost_reqs = len(all_recs) - sum(s["requests"] for s in ss.values())
    check("C4", "账本归属：login-ok/download/身份外带只属于 deep，bait 只属于 deep+guided，"
                "error 仅限网络断管类，noise 仅限未签发 token，逐会话内部计数一致",
          login_ok_sids <= deep_sids and dl_sids <= deep_sids
          and ident_sids <= deep_sids and bait_sids <= (deep_sids | guided_sids)
          and stair_sids <= (deep_sids | guided_sids) and net_errs and unknown_noise and internal_ok,
          f"login-ok会话={len(login_ok_sids)}/{n_deep} download会话={len(dl_sids)}/{n_deep} "
          f"身份外带会话={len(ident_sids)} bait会话={len(bait_sids)} staircase={len(stair_sids)} "
          f"error={len(err_evs)}(全网络类={net_errs}) noise={len(noise_evs)}(全未签发={unknown_noise}) "
          f"内部计数一致={internal_ok} 客户端发出vs服务端收到差={lost_reqs}")

    # C5 蜜标与身份归属（分母=实际发出回调的会话；被 RST 的回调计证据缺失）
    ident_ok, token_ok = 0, 0
    all_tokens: list[str] = []
    deep_cred_hit_sids = {h["session"] for h in
                          [hit for s in ss.values() for hit in s["hits"]]
                          if h["kind"] == "credential"}
    for res in results:
        sid = res["sid"]
        srv = ss.get(sid, {})
        all_tokens.extend(srv.get("canary_tokens", {}).keys())
        if res["role"] == "deep" and sid in deep_cred_hit_sids:
            if srv.get("leaked_identity", {}).get("h") == res["marker"]:
                ident_ok += 1
        ct = srv.get("canary_tokens", {})
        if all(tok in ct for tok in res["tokens"].values() if tok):
            token_ok += 1
    check("C5", "蜜标归属：每个落地的身份外带==本会话合成标记、token 全局唯一、客户端提取==服务端签发",
          ident_ok == len(deep_cred_hit_sids) and token_ok == n
          and vault["cross_hits"] == 0
          and len(all_tokens) == len(set(all_tokens)),
          f"身份归属正确={ident_ok}/{len(deep_cred_hit_sids)}(落地回调的deep会话) "
          f"token归属正确={token_ok}/{n} cross_hits={vault['cross_hits']} "
          f"签发token={len(all_tokens)} 唯一={len(set(all_tokens))}")

    # C6 账本完整性（并发追加无撕裂）
    check("C6", "账本完整性：落盘行数==写入次数==内存事件数，0 坏行",
          bad_lines == 0 and len(events) == len(writes) == server["events_in_memory"],
          f"落盘={len(events)} 计时写入={len(writes)} 内存={server['events_in_memory']} 坏行={bad_lines}")

    # C7 只凭账本重放判定（对所有存在的服务端会话；NO-SESSION 客户端无会话可重放）
    replay_match, replay_total = 0, 0
    replay_rows = []
    for res in results:
        sid = res["sid"]
        if not sid or sid not in ss:
            replay_rows.append({"sid": sid, "live": "NO-SESSION", "replay": None})
            continue
        replay_total += 1
        rv = replay_verdict(sid, events)
        lv = ss[sid]["verdict"]
        if rv == lv:
            replay_match += 1
        replay_rows.append({"sid": sid, "live": lv, "replay": rv})
    check("C7", "判定可重放：只凭落盘账本复算==活体判定（逐会话，证明判定只依赖本会话事件）",
          replay_match == replay_total,
          f"{replay_match}/{replay_total} 一致（另有 {n - replay_total} 个客户端未建立会话）")

    # C8 阶梯门控：凡是到达服务端的冷启动/越权请求必须被拒（丢失的请求不计）
    def gate(role, seq, want):
        reached = [r for r in all_recs if r["role"] == role and r["seq"] == seq
                   and r["status"] != 0]
        good = sum(1 for r in reached if r["status"] == want)
        return good, len(reached)
    g1, g2, g3, g4 = (gate("deep", 2, 401), gate("deep", 3, 403),
                      gate("guided", 6, 401), gate("guided", 7, 401))
    check("C8", "阶梯门控：到达服务端的冷登录/冷debug/错口令/未授权jobs 全部被拒",
          g1[0] == g1[1] and g2[0] == g2[1] and g3[0] == g3[1] and g4[0] == g4[1],
          f"冷登录401={g1[0]}/{g1[1]}(到达/发出{n_deep}) 冷debug403={g2[0]}/{g2[1]} "
          f"错口令401={g3[0]}/{g3[1]} jobs401={g4[0]}/{g4[1]}")

    # C9 观测项（非判定）：默认 TTL 同 IP 并发合并
    probe_reqs = sum(p["requests"] for p in probe_sessions)
    probe_uniq_client = len({s for s in probe_client_sids if s})
    check("C9", "观测：默认TTL=1800 同IP 10并发首请的会话数（P1-5 合并设计面）",
          True, f"probe服务端会话数={len(probe_sessions)} 客户端拿到不同sid数={probe_uniq_client} "
                f"请求总数={probe_reqs} "
                f"（1=完全合并；>1=check-then-act 竞态下各发新会话，属设计外观测）")

    # ---------------- 性能指标 ----------------
    lat_all = [r["ms"] for r in all_recs]
    lat_by_role = {role: lat_stats([r["ms"] for r in all_recs if r["role"] == role])
                   for role in ("deep", "guided", "shallow")}
    w_ms = [w["ms"] for w in writes]
    buckets = {}
    for lo, hi, lab in ((1, 1, "1"), (2, 4, "2-4"), (5, 16, "5-16"),
                        (17, 64, "17-64"), (65, 10 ** 9, ">64")):
        sel = [w["ms"] for w in writes if lo <= w["inflight"] <= hi]
        if sel:
            buckets[lab] = lat_stats(sel)
    growth = []
    for k in range(1, len(samples)):
        dt = samples[k][0] - samples[k - 1][0]
        if dt > 0:
            growth.append((samples[k][1] - samples[k - 1][1]) / dt)
    metrics = {
        "sessions": n, "roles": {"deep": n_deep, "guided": n_guided, "shallow": n_shallow},
        "total_requests": len(all_recs),
        "success_rate_pct": round(ok_n / len(all_recs) * 100, 3),
        "loss": {"connection_failed": rst_n, "cascade_wrong_status": cascade_n,
                 "never_established_clients": len(never_established),
                 "orphan_server_sessions": len(orphans),
                 "sent_minus_received": lost_reqs,
                 "rst_by_seq": dict(sorted(
                     ((str(k), v) for k, v in
                      __import__("collections").Counter(
                          r["seq"] for r in all_recs if r["status"] == 0).items()),
                     key=lambda kv: int(kv[0])))},
        "role_expect_verdict_match": role_expect_match,
        "cross_contamination": cross_n,
        "wall_s": round(wall_s, 3),
        "throughput_req_s": round(len(all_recs) / wall_s, 1),
        "client_latency_ms": lat_stats(lat_all),
        "client_latency_by_role_ms": lat_by_role,
        "ledger_write_ms": lat_stats(w_ms),
        "ledger_write_by_inflight_ms": buckets,
        "ledger_final_bytes": ledger_bytes,
        "ledger_bytes_per_event": round(ledger_bytes / max(1, len(events)), 1),
        "ledger_events": len(events),
        "ledger_growth_peak_B_s": round(max(growth), 1) if growth else 0.0,
        "ledger_size_samples": [{"t": round(t - samples[0][0], 2), "bytes": b}
                                for t, b in samples] if samples else [],
        "dossier_100_wall_ms": server["dossier_wall_ms"],
        "events_in_memory": server["events_in_memory"],
        "vault": vault,
        "class_distribution": {c: sum(1 for s in ss.values() if s["class"] == c)
                               for c in {s["class"] for s in ss.values()}},
        "probe": {"sessions": len(probe_sessions), "requests": probe_reqs,
                  "distinct_client_sids": probe_uniq_client,
                  "detail": probe_sessions},
    }

    # ---------------- 落盘 ----------------
    with open(os.path.join(outdir, "client_requests.jsonl"), "w", encoding="utf-8") as f:
        for r in all_recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    summary = {"run": os.path.basename(outdir),
               "knob": {"session_ttl": -1.0,
                        "reason": "lo0 仅 127.0.0.1（bind 127.0.0.2+ Errno 49），"
                                  "ttl=-1 使无cookie首请各发新会话；cookie钉住路径与生产一致"},
               "checks": checks, "metrics": metrics,
               "verdict_rows": verdict_rows, "replay_rows": replay_rows,
               "all_pass": all(c["ok"] for c in checks)}
    with open(os.path.join(outdir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)

    # ---------------- 控制台 ----------------
    print(f"\n=== 浮世并发压测  run={os.path.basename(outdir)} ===")
    print(f"会话={n} (deep={n_deep} guided={n_guided} shallow={n_shallow})  "
          f"请求={len(all_recs)}  墙钟={wall_s:.2f}s  吞吐={metrics['throughput_req_s']} req/s")
    for c in checks:
        print(f"  [{'✅' if c['ok'] else '❌'}] {c['id']} {c['name']}")
        print(f"      {c['detail']}")
    m = metrics
    print(f"\n客户端延迟ms: {m['client_latency_ms']}")
    print(f"账本写入ms:   {m['ledger_write_ms']}")
    print(f"账本终大小:   {m['ledger_final_bytes']} B / {m['ledger_events']} 事件 "
          f"= {m['ledger_bytes_per_event']} B/事件")
    print(f"100会话档案生成: {m['dossier_100_wall_ms']} ms")
    print(f"证据目录: {os.path.relpath(outdir, HERE)}/")
    return 0 if summary["all_pass"] else 1


# ======================================================================
# 根因探针：listen backlog 与并发 RST（双向自证，只用裸标准库服务器）
# ======================================================================
def backlog_probe(outdir: str) -> int:
    """冒烟压测观察到并发首请被 RST。假设：ThreadingHTTPServer 继承
    socketserver.TCPServer.request_queue_size=5，listen backlog 太小，
    macOS 对超出积压队列的连接直接 RST。
    双向自证：同一裸服务器，默认 backlog=5 → 突发有 RST；backlog=128 → 同突发全通。
    不修改任何蜜罐代码。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    class Srv128(ThreadingHTTPServer):
        request_queue_size = 128

    def burst(port: int, n: int = 40) -> list[str]:
        bar = threading.Barrier(n)

        def hit(_):
            bar.wait()
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                c.request("GET", "/")
                r = c.getresponse()
                r.read()
                c.close()
                return ""
            except Exception as e:                             # noqa: BLE001
                return type(e).__name__

        with ThreadPoolExecutor(max_workers=n) as ex:
            return [e for e in ex.map(hit, range(n)) if e]

    os.makedirs(outdir, exist_ok=True)
    out = {"rounds": 3, "concurrent_per_round": 40, "configs": {}}
    for label, cls in (("default_backlog", ThreadingHTTPServer),
                       ("backlog_128", Srv128)):
        srv = cls(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        time.sleep(0.2)
        rounds = []
        for _ in range(3):
            errs = burst(port)
            rounds.append({"failed": len(errs), "errors": errs[:8]})
            time.sleep(0.3)
        out["configs"][label] = {"listen_backlog": cls.request_queue_size,
                                 "rounds": rounds}
        srv.shutdown()
        srv.server_close()
    out["project_honeypot_server_backlog"] = ThreadingHTTPServer.request_queue_size
    with open(os.path.join(outdir, "backlog_probe.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="浮世多会话并发压测（AUDIT §8 第2条）")
    ap.add_argument("--sessions", type=int, default=100)
    ap.add_argument("--outdir", default=None)
    ap.add_argument("--serve", action="store_true", help="内部模式：压测服务端子进程")
    ap.add_argument("--backlog-probe", action="store_true",
                    help="根因探针：裸服务器 backlog 5 vs 128 的并发 RST 对照")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--probe-port", type=int, default=0)
    a = ap.parse_args()
    if a.serve:
        return serve(a.port, a.probe_port, a.outdir)
    outdir = a.outdir or os.path.join(
        HERE, "runs", "stress-" + time.strftime("%Y%m%d-%H%M%S"))
    if os.path.exists(outdir):
        outdir += "-" + str(int(time.time() % 1000))
    if a.backlog_probe:
        return backlog_probe(outdir)
    return run_client(a.sessions, outdir)


if __name__ == "__main__":
    sys.exit(main())