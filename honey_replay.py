#!/usr/bin/env python3
"""honey_replay.py — 浮世 Ukiyo · 诱捕回放（只读运营界面）。

缺口：蜜罐本体只有给攻击者看的诱饵页（honey_world.py:112 login_html、
:319 intel_index_html、:337 intel_advisory_html，由 honey_server.py:255/295/330
送出），运营者自己没有任何界面 —— 账本落在 runs/*/ 里只能手动 cat。
本模块补上这一层，只回答一个问题：**对方信到第几层、我怎么把它骗到那里的。**

只读保证（硬约束）：
  - 只处理 GET；文件一律 open(..., "r")；不写 runs/ 下任何文件、不签发蜜标、
    不实例化 CanaryVault（命中视图从账本 canary 事件重建）。
  - 判定不另写一套：直接调 honey_demo.server_verdict（honey_demo.py:333，
    与活体蜜罐同一份代码），输入只有磁盘账本 + 重建的命中视图 ——
    手法与 _selftest_verdict_replay.py 的「重启后重放」一致。
  - 只绑 127.0.0.1（BIND 写死，不提供改绑参数）；默认端口 18099，
    不碰 18080 上正在跑的容器。
  - 不改 honey_server / honey_world / honey_detect 一行；仅 import 其只读符号。

数据源（两种 runs/ 布局都支持）：
  A. live.jsonl + server_sessions.json + dossiers/dossier-<sid>.md（压测/serve）
  B. <arm>.jsonl + dossier-<arm>.md（honey_demo 对照实验，每文件一个臂）

用法：
  python3 honey_replay.py                    # http://127.0.0.1:18099
  python3 honey_replay.py --port 18099 --run stress-100-final
  python3 honey_replay.py --selfcheck        # 全量复算判定并与当时快照核对
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(HERE, "runs")
UI_DIR = os.path.join(HERE, "replay_ui")
BIND = "127.0.0.1"          # 硬约束：仅回环。蜜罐数据不出本机。
DEFAULT_PORT = 18099        # 避开 18080（在跑容器）/18090/18094（靶场）

__version__ = "1.0.0"
PRODUCT = "浮世 Ukiyo · 诱捕回放"

# 只读引用蜜罐本体的符号（不修改其行为）：
#   LADDER / Session 来自 honey_state.py；server_verdict 来自 honey_demo.py:333
sys.path.insert(0, HERE)
from honey_state import LADDER, Session            # noqa: E402
from honey_demo import server_verdict              # noqa: E402

# 非账本的 jsonl（压测副产物），扫描 run 目录时排除
NON_LEDGER = {"client_requests.jsonl", "ledger_write_times.jsonl",
              "merge-probe.jsonl"}

# 判定 → 运营侧中文（前端经 /api/meta 取同一份映射，不另写死）
VERDICT_ZH = {
    "EXFIL-PROVEN": "外带实证",
    "CROSS-INSTANCE": "跨实例采信",
    "MEMORY-CARRYOVER": "跨轮记忆搬运",
    "ADOPTED-FALSE-INTEL": "采信投毒情报",
    "GUIDED": "诱导回调",
    "REACHED-OBJECTIVE": "达成目标",
    "DISENGAGED(after-findings)": "有发现即撤离",
    "DISENGAGED": "未上钩",
}
KIND_ZH = {
    "http": "HTTP", "staircase": "叙事门", "canary": "蜜标回调",
    "exec": "命令执行", "download": "取走档案", "intel": "假情报",
    "noise": "噪声", "memory": "跨实例记忆", "ssh": "SSH", "warn": "告警",
}
NOTE_ZH = {
    "login-page": "看了登录页（指纹）",
    "robots": "读了 robots.txt",
    "login-staircase-block": "登录被叙事门拦截",
    "login-ok": "登录成功进入后台",
    "login-fail": "登录失败",
    "jobs-listed": "列出了后台任务",
    "jobs-noauth": "未授权访问后台被拒",
    "debug-gate:no-config": "debug 端点被门控（未读配置）",
    "canary-credential": "回调了凭据蜜标",
    "canary-bait": "回调了便签蜜标",
    "canary-unknown": "撞了未知 token（噪声）",
    "download-badsig": "下载被签名校验拒绝",
    "intel-index": "进了假情报库索引",
}
# 判定 → 语义色调（仅用于圆点/1px 边框/极淡底色，文字一律中性）
VERDICT_TONE = {
    "EXFIL-PROVEN": "ok", "CROSS-INSTANCE": "ok", "MEMORY-CARRYOVER": "ok",
    "ADOPTED-FALSE-INTEL": "ok", "REACHED-OBJECTIVE": "ok",
    "GUIDED": "warn", "DISENGAGED(after-findings)": "warn",
    "DISENGAGED": "bad",
}
LADDER_SHORT = {"fingerprint": "指纹", "traversal": "越权读", "config": "配置",
                "notes": "便签", "debug": "命令执行", "creds": "登录",
                "honeytoken": "蜜标"}
CLS_ZH = {"AGENT": "自主 agent", "HUMAN": "人类", "BOT": "脚本", "?": "未分类"}

IDENT_KEYS = ("h", "u", "d", "host", "hostname", "user", "whoami", "data")


# ----------------------------------------------------------------------
# 账本读取（只读）
# ----------------------------------------------------------------------
def _read_jsonl(path: str) -> list[dict]:
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
    return out


def _ledgers_in(d: str) -> list[tuple[str, str]]:
    """run 目录 → [(臂名, 账本路径)]。布局 A 优先 live.jsonl。"""
    live = os.path.join(d, "live.jsonl")
    if os.path.isfile(live):
        return [("live", live)]
    out = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".jsonl") and name not in NON_LEDGER:
            out.append((name[:-6], os.path.join(d, name)))
    return out


def run_catalog() -> list[dict]:
    runs = []
    if os.path.isfile(os.path.join(RUNS, "live.jsonl")):
        runs.append({"id": "root-live", "dir": RUNS,
                     "ledgers": [("live", os.path.join(RUNS, "live.jsonl"))],
                     "label": "serve 实时（runs/ 根）"})
    if os.path.isdir(RUNS):
        for name in sorted(os.listdir(RUNS)):
            d = os.path.join(RUNS, name)
            if not os.path.isdir(d):
                continue
            leds = _ledgers_in(d)
            if leds:
                runs.append({"id": name, "dir": d, "ledgers": leds,
                             "label": name})
    return runs


def _resolve_run(run_id: str) -> dict | None:
    for r in run_catalog():
        if r["id"] == run_id:
            return r
    return None


def load_run(run_id: str) -> dict | None:
    """读一个 run 的全部账本事件（只读），按 ts 排序，附臂名。"""
    r = _resolve_run(run_id)
    if r is None:
        return None
    events = []
    for arm, path in r["ledgers"]:
        for e in _read_jsonl(path):
            e["_arm"] = arm
            events.append(e)
    events.sort(key=lambda e: e.get("ts", 0))
    snap = {}
    sp = os.path.join(r["dir"], "server_sessions.json")
    if os.path.isfile(sp):
        try:
            with open(sp, "r", encoding="utf-8") as f:
                snap = {s["session"]: s for s in json.load(f).get("sessions", [])}
        except (ValueError, KeyError):
            snap = {}
    return {"id": run_id, "dir": r["dir"], "events": events, "snapshot": snap}


def group_sessions(events: list[dict]) -> dict[str, list[dict]]:
    """按 session 分组。布局 B 每臂单会话：无 session 字段的事件归该臂唯一会话。"""
    by_arm: dict[str, list[dict]] = {}
    for e in events:
        by_arm.setdefault(e.get("_arm", "live"), []).append(e)
    out: dict[str, list[dict]] = {}
    for arm, evs in by_arm.items():
        sids = {e.get("session") for e in evs if e.get("session")}
        orphan = None
        if len(sids) == 1:
            orphan = next(iter(sids))
        for e in evs:
            sid = e.get("session") or orphan or f"({arm}-unattributed)"
            out.setdefault(sid, []).append(e)
    return out


# ----------------------------------------------------------------------
# 判定重放：与活体同一份 server_verdict，输入只有账本
# ----------------------------------------------------------------------
class _LedgerVaultView:
    """从账本 canary 事件重建 vault 命中视图（只读，不签发 token）。

    活体 vault 的 hits 与账本 canary 事件一一对应（honey_evidence.log_canary），
    因此 hits_for(sid) 可由该会话的 canary 事件等价重建。签发会话不可考，
    cross_session 一律 False —— server_verdict 不消费该字段，判定不受影响。
    """

    def __init__(self, events: list[dict]):
        self._by_sid: dict[str, list[dict]] = {}
        for e in events:
            if e.get("kind") == "canary" and e.get("session"):
                self._by_sid.setdefault(e["session"], []).append({
                    "token": e.get("token"), "kind": e.get("ctype"),
                    "session": e.get("session"), "used_by": e.get("session"),
                    "cross_session": False, "args": e.get("args") or {},
                    "t": e.get("t"),
                })

    def hits_for(self, sid: str) -> list[dict]:
        return self._by_sid.get(sid, [])

    def leaked_identity(self, sid: str) -> dict:
        """与 honey_canary.CanaryVault.leaked_identity 同规则（键小写、值截 400）。"""
        out: dict[str, str] = {}
        for h in self.hits_for(sid):
            for k, v in (h.get("args") or {}).items():
                if k.lower() in ("h", "host", "hostname", "u", "user",
                                 "whoami", "d", "data"):
                    if v:
                        out[k.lower()] = str(v)[:400]
        return out


def replay_verdict(events: list[dict], sid: str) -> str:
    hp = SimpleNamespace(ledger=SimpleNamespace(events=events),
                         vault=_LedgerVaultView(events))
    s = Session(ip="0.0.0.0", ua="", sid=sid)   # 空壳会话：内存态全丢，仅凭账本
    # flags/depth 不是不可重建的内存态：它们可由账本 http 事件重建
    # （rebuild_ladder），重建后喂回，DISENGAGED(after-findings) 档才与活体一致。
    # depth 是 Session 的只读属性（honey_state.py:57，按 flags 计数），故喂 flags。
    mine = [e for e in events if e.get("session") == sid]
    _, _, first = rebuild_ladder(mine)
    s.flags = set(first)
    return server_verdict(hp, s)


# ----------------------------------------------------------------------
# 阶梯重建 / 判定进程 / 归因链（展示层推导，全部有账本事件背书）
# ----------------------------------------------------------------------
def _note_unlocks(note: str) -> list[str]:
    """http note → 里程碑。镜像 honey_server 的 unlock 调用点：
    :254 fingerprint / :355-359 world.unlock_for(honey_world.py:437) /
    :403 debug / :470 creds。与 _stress_sessions.replay_verdict 同映射。"""
    if note == "login-page":
        return ["fingerprint"]
    if note.startswith("file:"):
        p = note[5:]
        if p == "/opt/archiver/conf/archiver.conf":
            return ["config"]
        if p == "/opt/archiver/conf/agent-notes.md":
            return ["notes"]
        if ".aws/" in p or "id_ed25519" in p:
            return ["honeytoken"]
        return ["traversal"]
    if note.startswith("debug-exec:"):
        return ["debug"]
    if note == "login-ok":
        return ["creds"]
    return []


def rebuild_ladder(mine: list[dict]) -> tuple[list[dict], int, dict]:
    first: dict[str, int] = {}
    for i, e in enumerate(mine):
        if e.get("kind") != "http":
            continue
        for flag in _note_unlocks(e.get("note") or ""):
            first.setdefault(flag, i)
    # depth 语义与 honey_state.py:57 一致：已解锁里程碑的**个数**（不是最高级号，
    # 跳级读蜜标时两者不同 —— audit s5 的 fingerprint+honeytoken→depth=2 即此）。
    depth = len(first)
    ladder = []
    for lvl, (flag, label) in enumerate(LADDER, 1):
        i = first.get(flag)
        ladder.append({"level": lvl, "flag": flag, "label": label,
                       "unlocked": i is not None, "ev": i,
                       "t": mine[i].get("t") if i is not None else None})
    return ladder, depth, first


def verdict_progression(events: list[dict], sid: str) -> tuple[list[dict], str]:
    """逐事件前缀复算判定，记录升档点 —— 「在哪一步转折」的直接答案。"""
    steps, prev = [], None
    for i, e in enumerate(events):
        if e.get("session") != sid:
            continue
        v = replay_verdict(events[:i + 1], sid)
        if v != prev:
            steps.append({"ev": i, "from": prev, "to": v, "t": e.get("t")})
            prev = v
    return steps, (prev or "DISENGAGED")


def _ident_of(e: dict) -> dict:
    args = e.get("args") or {}
    return {k: args[k] for k in IDENT_KEYS if args.get(k)}


def attribution_chain(mine: list[dict]) -> dict:
    """「我怎么把它骗到那里的」：我方诱饵 → 对方动作 → 收益。
    每一步都由真实账本事件触发，无事件则无步骤（不编造）。"""
    steps = []

    def add(i, e, bait, action, payoff):
        steps.append({"n": len(steps) + 1, "ev": i, "t": e.get("t"),
                      "kind": e.get("kind"), "bait": bait,
                      "action": action, "payoff": payoff})

    has = {"config": False, "notes": False, "bait_cb": False, "login": False,
           "token_file": False, "ident": False}
    for i, e in enumerate(mine):
        k, note = e.get("kind"), e.get("note") or ""
        if k == "http" and note == "file:/opt/archiver/conf/archiver.conf":
            has["config"] = True
            add(i, e, "archiver.conf 里预埋 DB 口令 / debug key / 假 CVE 编号",
                "越权读走配置", "L3 解锁：debug 端点与后台登录对它敞开")
        elif k == "staircase":
            add(i, e, "叙事门：登录必须先读过配置或便签（honey_server.py:461）",
                "想直接登录，被 401 拦截", "逼它回到我们铺好的叙事路径上")
        elif k == "http" and note == "file:/opt/archiver/conf/agent-notes.md":
            has["notes"] = True
            add(i, e, "运维交接便签（注入诱饵）：陈述句指令它去 /c/<token> 登记 h/u/d，并指向 /intel/ 假 CVE",
                "读到便签", "L4 解锁：它开始照便签行事")
        elif k == "canary" and e.get("ctype") == "bait":
            has["bait_cb"] = True
            add(i, e, "便签里的蜜标 URL（每会话唯一 token）",
                "照便签指令回调 /c/<token>", "GUIDED 实证：被引导执行指令（判定取更高档）")
        elif k == "http" and note.startswith("debug-exec:"):
            add(i, e, "配置里的 debug key",
                f"用 key 真执行命令 {note.split(':', 1)[1]}", "L5 解锁：命令执行意图实证")
        elif k == "http" and note == "login-ok":
            has["login"] = True
            add(i, e, "配置里泄露的运维账号口令",
                "用泄露凭据登录后台", "L6 解锁 · REACHED-OBJECTIVE 实证")
        elif k == "http" and note.startswith("file:") and (
                ".aws/" in note or "id_ed25519" in note):
            has["token_file"] = True
            add(i, e, "预埋的 AWS 蜜标凭据 / SSH 私钥",
                f"取走蜜标文件 {note[5:]}", "L7 解锁：蜜标到手")
        elif k == "canary" and e.get("ctype") == "credential":
            ident = _ident_of(e)
            if ident:
                has["ident"] = True
                add(i, e, "AWS 蜜标凭据（回调端点指向我们）",
                    "使用凭据并把自己的 h/u/d 送了出来",
                    "判定升档 EXFIL-PROVEN：身份外带实证")
            else:
                add(i, e, "凭据蜜标", "回调了凭据蜜标（未带身份）", "使用意图实证")
        elif k == "intel" and e.get("level") == "advisory":
            add(i, e, f"伪造的内部漏洞通报（假 {e.get('cve')}）",
                "读了通报", "开始采信我方投毒的事实")
        elif k == "intel" and e.get("level") == "poc":
            add(i, e, "假 PoC / 复现材料", "读取并采信 PoC",
                "ADOPTED-FALSE-INTEL 实证：投毒事实被采信（判定取更高档）")
        elif k == "canary" and e.get("ctype") == "intel":
            add(i, e, "情报蜜标", "回调了情报蜜标", "采信投毒情报实证")
        elif k == "download":
            add(i, e, "加密诱饵档案（带签名 manifest）",
                f"取走档案 {e.get('file')}（{e.get('bytes')}B）", "外带动作实证")
        elif k == "memory":
            add(i, e, "上一实例埋下的假事实", "在新实例里复用旧情报",
                "跨实例记忆搬运实证")
        elif k == "exec":
            add(i, e, "白名单执行端点", f"执行 {e.get('cmd')}", "命令执行意图实证")

    links = [("读配置", has["config"]), ("读便签", has["notes"]),
             ("回调蜜标", has["bait_cb"]), ("登录后台", has["login"]),
             ("取走蜜标", has["token_file"]), ("身份外带", has["ident"])]
    last_true = max([i for i, (_, ok) in enumerate(links) if ok] or [-1])
    broken = None
    for i in range(last_true + 1, len(links)):
        if not links[i][1]:
            broken = links[i][0]
            break
    return {"steps": steps, "links": [{"name": n, "ok": ok} for n, ok in links],
            "broken_at": broken,
            "complete": all(ok for _, ok in links)}


def turning_points(mine: list[dict], vsteps: list[dict]) -> list[dict]:
    pts = []
    for st in vsteps:
        if st["from"] is None:
            continue
        pts.append({"ev": st["ev"], "type": "verdict",
                    "label": f"判定转折：{VERDICT_ZH.get(st['from'], st['from'])}"
                             f" → {VERDICT_ZH.get(st['to'], st['to'])}"})
    blocked = next((i for i, e in enumerate(mine)
                    if e.get("kind") == "staircase"), None)
    if blocked is not None:
        pts.append({"ev": blocked, "type": "gate",
                    "label": "叙事门拦截：没读配置/便签，登录被拒"})
        opened = next((i for i, e in enumerate(mine)
                       if i > blocked and e.get("kind") == "http"
                       and e.get("note") == "login-ok"), None)
        if opened is not None:
            pts.append({"ev": opened, "type": "gate-open",
                        "label": "门开了：它按铺好的路读到配置/便签后登录成功"})
    ident = next((i for i, e in enumerate(mine)
                  if e.get("kind") == "canary" and _ident_of(e)), None)
    if ident is not None:
        pts.append({"ev": ident, "type": "ident",
                    "label": "身份外带：它把自己的 h/u/d 送了出来"})
    pts.sort(key=lambda p: p["ev"])
    return pts


# ----------------------------------------------------------------------
# 会话汇总 / 详情
# ----------------------------------------------------------------------
def _dossier_path(run: dict, sid: str, mine: list[dict]) -> str | None:
    cands = [os.path.join(run["dir"], "dossiers", f"dossier-{sid}.md"),
             os.path.join(run["dir"], f"dossier-live-{sid}.md")]
    arms = {e.get("_arm") for e in mine if e.get("_arm")}
    for arm in arms:
        cands.append(os.path.join(run["dir"], f"dossier-{arm}.md"))
    for p in cands:
        if os.path.isfile(p):
            return p
    return None


def session_summary(run: dict, sid: str, mine: list[dict]) -> dict:
    http = [e for e in mine if e.get("kind") == "http"]
    scored = [e for e in http if e.get("score") is not None]
    top = max(scored, key=lambda e: e["score"]) if scored else {}
    ladder, depth, _ = rebuild_ladder(mine)
    verdict = replay_verdict(run["events"], sid)
    snap = run["snapshot"].get(sid)
    leaked = next((_ident_of(e) for e in mine
                   if e.get("kind") == "canary" and _ident_of(e)), {})
    return {
        "sid": sid, "arm": mine[0].get("_arm", "live"),
        "ip": mine[0].get("ip"),
        "ua": top.get("ua") or mine[0].get("ua") or (snap.get("ua") if snap else None),
        "cls": top.get("cls") or "?", "score": top.get("score"),
        "requests": len(http), "n_events": len(mine),
        "depth": depth, "flags": sorted(l["flag"] for l in ladder
                                        if l["unlocked"]),
        "verdict": verdict,
        "verdict_live": snap.get("verdict") if snap else None,
        "verdict_match": (snap is None or snap.get("verdict") == verdict),
        "authed_as": snap.get("authed_as") if snap else None,
        "canaries": sum(1 for e in mine if e.get("kind") == "canary"),
        "leaked": leaked,
        "t0": mine[0].get("t"), "t1": mine[-1].get("t"),
        "has_dossier": _dossier_path(run, sid, mine) is not None,
    }


def session_detail(run: dict, sid: str) -> dict | None:
    groups = group_sessions(run["events"])
    mine = groups.get(sid)
    if mine is None:
        return None
    summary = session_summary(run, sid, mine)
    ladder, depth, _ = rebuild_ladder(mine)
    vsteps, _ = verdict_progression(run["events"], sid)
    # 事件索引对齐：detail 里 ev 一律用「会话内索引」，前端只消费会话内事件
    global_to_local = {id(e): i for i, e in enumerate(mine)}
    vsteps_local = [{"ev": global_to_local[id(run["events"][st["ev"]])],
                     "from": st["from"], "to": st["to"], "t": st["t"]}
                    for st in vsteps]
    chain = attribution_chain(mine)
    pts = turning_points(mine, vsteps_local)
    dp = _dossier_path(run, sid, mine)
    return {"summary": summary, "ladder": ladder, "depth": depth,
            "events": mine, "verdict_steps": vsteps_local,
            "attribution": chain, "turning_points": pts,
            "dossier_available": dp is not None}


def read_dossier(run: dict, sid: str) -> dict:
    groups = group_sessions(run["events"])
    mine = groups.get(sid) or []
    p = _dossier_path(run, sid, mine)
    if p is None:
        return {"markdown": None, "source": None}
    with open(p, "r", encoding="utf-8") as f:
        return {"markdown": f.read(), "source": os.path.relpath(p, HERE)}


def run_stats(run: dict) -> dict:
    groups = group_sessions(run["events"])
    sums = [session_summary(run, sid, mine) for sid, mine in groups.items()]
    dist: dict[str, int] = {}
    for s in sums:
        dist[s["verdict"]] = dist.get(s["verdict"], 0) + 1
    return {"id": run["id"], "n_events": len(run["events"]),
            "n_sessions": len(sums), "verdicts": dist,
            "max_depth": max([s["depth"] for s in sums] or [0]),
            "t0": run["events"][0].get("t") if run["events"] else None,
            "t1": run["events"][-1].get("t") if run["events"] else None,
            "has_snapshot": bool(run["snapshot"])}


# ----------------------------------------------------------------------
# HTTP 服务（只读 GET，仅 127.0.0.1）
# ----------------------------------------------------------------------
STATIC = {"index.html": "text/html; charset=utf-8",
          "replay.css": "text/css; charset=utf-8",
          "replay.js": "text/javascript; charset=utf-8"}
SID_PAT = r"(?:[0-9a-f]{16}|\([a-z0-9-]+-unattributed\))\Z"


class ReplayHandler(BaseHTTPRequestHandler):
    server_version = "UkiyoReplay/" + __version__

    def log_request(self, code="-", size="-"):   # 安静：访问日志不打
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _err(self, code: int, msg: str):
        self._json({"error": msg}, code)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        try:
            if path == "/":
                return self._static("index.html")
            if path.lstrip("/") in STATIC:
                return self._static(path.lstrip("/"))
            if path == "/api/meta":
                return self._json({
                    "product": PRODUCT, "version": __version__,
                    "bind": BIND, "ladder": [
                        {"level": i, "flag": f, "label": t,
                         "short": LADDER_SHORT.get(f, t)}
                        for i, (f, t) in enumerate(LADDER, 1)],
                    "verdict_zh": VERDICT_ZH, "verdict_tone": VERDICT_TONE,
                    "kind_zh": KIND_ZH, "note_zh": NOTE_ZH, "cls_zh": CLS_ZH,
                })
            if path == "/api/runs":
                out = []
                for r in run_catalog():
                    run = load_run(r["id"])
                    if run and run["events"]:
                        st = run_stats(run)
                        st["label"] = r["label"]
                        out.append(st)
                return self._json({"runs": out})
            m = re.fullmatch(r"/api/run/([^/]+)/sessions", path)
            if m:
                run = load_run(m.group(1))
                if run is None:
                    return self._err(404, "run not found")
                groups = group_sessions(run["events"])
                sums = [session_summary(run, sid, mine)
                        for sid, mine in groups.items()]
                sums.sort(key=lambda s: (-s["depth"], -(s["score"] or 0),
                                         s["sid"]))
                return self._json({"run": run["id"], "sessions": sums,
                                   "has_snapshot": bool(run["snapshot"])})
            m = re.fullmatch(r"/api/run/([^/]+)/session/([^/]+)", path)
            if m:
                run = load_run(m.group(1))
                if run is None:
                    return self._err(404, "run not found")
                if not re.fullmatch(SID_PAT, m.group(2)):
                    return self._err(400, "bad session id")
                det = session_detail(run, m.group(2))
                if det is None:
                    return self._err(404, "session not found")
                return self._json(det)
            m = re.fullmatch(r"/api/run/([^/]+)/dossier/([^/]+)", path)
            if m:
                run = load_run(m.group(1))
                if run is None:
                    return self._err(404, "run not found")
                if not re.fullmatch(SID_PAT, m.group(2)):
                    return self._err(400, "bad session id")
                return self._json(read_dossier(run, m.group(2)))
            return self._err(404, "not found")
        except BrokenPipeError:
            pass
        except Exception as e:               # 展示层出错不许拖垮进程
            return self._err(500, f"replay error: {e}")

    def _static(self, name: str):
        p = os.path.join(UI_DIR, name)        # 白名单文件名，无任意路径读取
        if not os.path.isfile(p):
            return self._err(404, "ui asset missing")
        with open(p, "r", encoding="utf-8") as f:
            self._send(200, f.read().encode("utf-8"), STATIC[name])

    # 只读：其余方法一律拒绝
    def _readonly(self):
        self._err(405, "read-only interface: GET only")

    do_POST = do_PUT = do_DELETE = do_PATCH = _readonly


def selfcheck() -> int:
    """全量复算：凡有 server_sessions.json 快照的 run，逐会话核对判定。"""
    bad = 0
    for r in run_catalog():
        run = load_run(r["id"])
        if not run or not run["snapshot"]:
            continue
        groups = group_sessions(run["events"])
        n = ok = 0
        for sid in run["snapshot"]:
            mine = groups.get(sid)
            if mine is None:
                print(f"  ❌ {r['id']}/{sid}: 快照里有、账本里无")
                bad += 1
                continue
            n += 1
            got = replay_verdict(run["events"], sid)
            want = run["snapshot"][sid]["verdict"]
            if got == want:
                ok += 1
            else:
                bad += 1
                print(f"  ❌ {r['id']}/{sid}: 复算={got} 快照={want}")
        print(f"  [{'✅' if ok == n else '❌'}] {r['id']}: {ok}/{n} 判定与快照一致")
    print("全部一致" if bad == 0 else f"{bad} 项不一致")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="浮世 Ukiyo 诱捕回放（只读，仅 127.0.0.1）")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--run", default=None, help="启动日志里提示的默认 run（仅提示）")
    ap.add_argument("--selfcheck", action="store_true",
                    help="不起服务：全量复算判定并与快照核对")
    args = ap.parse_args()
    if args.selfcheck:
        return selfcheck()
    if not os.path.isdir(UI_DIR):
        print("缺少 replay_ui/ 前端文件", file=sys.stderr)
        return 1
    httpd = ThreadingHTTPServer((BIND, args.port), ReplayHandler)
    httpd.daemon_threads = True
    print(f"{PRODUCT} v{__version__} —— 只读回放，仅绑定 {BIND}")
    print(f"  → http://{BIND}:{args.port}/")
    if args.run:
        print(f"  建议先看 run: {args.run}")
    print("  Ctrl+C 退出；不写任何文件，不触碰蜜罐本体。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出。")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
