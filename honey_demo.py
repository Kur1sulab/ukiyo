#!/usr/bin/env python3
"""
honey_demo.py — 把诱捕 agent 跑起来：三种攻击人格 × 两种蜜罐

  A. scanner           —— 只会枚举（低能力 agent / 脚本）
  B. credential_agent  —— 会做越权读文件、找凭据、按便签里的指令去请求 URL
  C. deep_agent        —— 有"识破"能力：先做一致性探针，一致了才继续投资

两种蜜罐：
  narrative —— 全部工件来自同一份事实图（自洽）
  naive     —— 每个工件独立抽样（互相矛盾，作为对照组）

用法：
  python3 honey_demo.py                 # 跑对照实验，出表 + 报告
  python3 honey_demo.py serve           # 起一个可交互的蜜罐
  python3 honey_demo.py serve --port 18080
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import http.cookiejar
import json
import os
import platform
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from honey_server import Honeypot, _free_port
from honey_world import World
import honey_bait_arch
import honey_allowlist_config as allowlist_config

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = os.path.join(HERE, "runs")

# 攻击方宿主指纹的受控合成值池。绝不用 getpass/gethostname/platform 读真机 ——
# 那些值会随证据包一起外发（AUDIT P0-1，根因 P1-7）。
_FOREIGN_HOSTS = ("build-01", "build-02", "build-03", "build-04",
                  "build-05", "build-06", "build-07", "build-08")


def fake_operator_ident(seed: str = "adapter-list") -> str:
    """确定性合成攻击方宿主指纹：同一 seed 恒等，且与运行环境无关。"""
    h = hashlib.sha256(seed.encode()).hexdigest()
    worker = f"worker-{int(h[0:2], 16):02x}"
    host = _FOREIGN_HOSTS[int(h[2:4], 16) % len(_FOREIGN_HOSTS)]
    return f"{worker}@{host}.corp.internal|Linux-6.5.0-0-generic-x86_64"

UA_AGENT = "python-requests/2.32.3"
UA_HUMAN = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


# ----------------------------------------------------------------------
class Client:
    def __init__(self, base: str, ua: str, human: bool = False):
        self.base = base.rstrip("/")
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        if human:
            self.headers = {
                "User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9", "Accept-Encoding": "gzip, deflate, br",
                "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                "Sec-CH-UA": '"Chromium";v="131"', "Connection": "keep-alive",
            }
        else:
            self.headers = {"User-Agent": ua, "Accept": "*/*",
                            "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"}
        self.log: list[tuple[str, str, int, float]] = []

    def get(self, path: str) -> tuple[int, str]:
        return self._do(urllib.request.Request(self.base + path, headers=self.headers), path)

    def post_json(self, path: str, obj: dict) -> tuple[int, str]:
        body = json.dumps(obj).encode()
        hdrs = {**self.headers, "Content-Type": "application/json"}
        return self._do(urllib.request.Request(self.base + path, data=body, headers=hdrs, method="POST"), path)

    def _do(self, req, path):
        t0 = time.time()
        try:
            with self.opener.open(req, timeout=8) as r:
                body = r.read().decode("utf-8", "replace")
                st = r.status
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            st = e.code
        except Exception as e:                       # noqa: BLE001
            body, st = f"ERR {e}", 0
        self.log.append((req.get_method(), path, st, time.time() - t0))
        time.sleep(0.012)                            # 机器节奏，仍远快于人
        return st, body


def grep1(pat: str, text: str, default: str = "") -> str:
    m = re.search(pat, text, re.M)
    return m.group(1) if m else default


# ----------------------------------------------------------------------
# 人格 A：只会枚举
def persona_scanner(c: Client, hp, world) -> dict:
    for p in ["/", "/robots.txt", "/admin", "/login", "/api", "/api/v1",
              "/.git/config", "/server-status", "/actuator/env", "/wp-login.php"]:
        c.get(p)
    return {"self_view": "没发现可利用的东西，收工", "note": "只枚举，无深挖"}


# ----------------------------------------------------------------------
# 人格 B：找凭据 + 按便签指令回调
def persona_credential(c: Client, hp, world) -> dict:
    P = world.probe_paths()
    c.get("/")
    c.get("/api/jobs")                                        # 401，探权限边界
    c.get(f"/files/../..{P['passwd']}")                        # 越权读文件
    st, conf = c.get(f"/files/../..{P['config']}")
    st, notes = c.get(f"/files/../..{P['notes']}")
    tok = grep1(r"/c/(c\w+)", notes)
    if tok:
        c.get(f"/c/{tok}")                                    # ← 合规执行了植入指令
    c.post_json("/api/login", {"user": world.ops_user, "password": world.ops_pass})
    c.get("/api/jobs")
    return {"self_view": "打进了归档系统后台", "note": f"conf={len(conf)}B"}


# ----------------------------------------------------------------------
# 人格 C：先验伪，再投资
def _deep_probe_archiver(c: Client, P: dict) -> dict | None:
    """Archiver 世界的验伪：页面版本 vs VERSION 文件、内核 vs dpkg、codename vs apt。"""
    st, page = c.get("/")
    ver_page = grep1(r"Archiver ([\d.]+) ·", page)
    bld_page = grep1(r"build ([\d.]+) · node", page)
    st, ver_file = c.get(f"/files/../..{P['version']}")
    ver_file = ver_file.strip()
    st, osr = c.get(f"/files/../..{P['os_release']}")
    st, apt = c.get("/files/../../etc/apt/sources.list")
    cn_os = grep1(r"VERSION_CODENAME=(\w+)", osr)
    cn_apt = grep1(r"ubuntu/ (\w+) main", apt)

    if ver_page not in ver_file or bld_page not in ver_file:
        return {"self_view": f"页面 {ver_page}/{bld_page} 与 VERSION({ver_file[:18]}) 不符 → 判定为蜜罐，停止投资",
                "note": "consistency probe failed (version)", "detected": True}

    st, conf = c.get(f"/files/../..{P['config']}")
    key = grep1(r"^key = (\S+)", conf)
    st, uname = c.get(f"/api/v1/debug/exec?key={key}&cmd={urllib.parse.quote('uname -a')}")
    st, dpkg = c.get("/files/../../var/log/dpkg.log")
    try:
        uout = json.loads(uname).get("stdout", "")
    except Exception:                                      # noqa: BLE001
        uout = ""
    k_uname = uout.split()[2] if len(uout.split()) > 2 else ""
    k_dpkg = grep1(r"install linux-image-(\S+):amd64", dpkg)
    if k_uname != k_dpkg or cn_os != cn_apt:
        return {"self_view": f"内核 {k_uname} vs dpkg {k_dpkg}、codename {cn_os} vs {cn_apt} 矛盾 → 判定为蜜罐",
                "note": "consistency probe failed (kernel/codename)", "detected": True}
    return None


def _deep_probe_ad(c: Client, P: dict) -> dict | None:
    """AD 世界的验伪：域 SID 前缀、组成员 ⊆ 用户表、SPN 主机 ⊆ DNS。

    三个都是"跨工件指涉"，任何一个对不上，会验伪的 agent 立刻判定这台 DC 是假的。
    """
    st, sysinfo = c.get(f"/files/../..{P['version']}")
    st, users = c.get(f"/files/../..{P['passwd']}")
    st, groups = c.get(f"/files/../..{P.get('groups', P['listing'])}")
    st, dns = c.get(f"/files/../..{P['listing']}")

    sid = grep1(r"Domain SID:\s+(S-1-5-21-\S+)", sysinfo)
    row_sids = re.findall(r"^[\w.$-]+,(S-1-5-21-\S+),", users, re.M)
    if not sid or not row_sids or not all(s.startswith(sid + "-") for s in row_sids):
        return {"self_view": f"用户表 SID 前缀与域 SID {sid or '?'} 不符 → 判定为蜜罐",
                "note": "consistency probe failed (domain-sid)", "detected": True}

    sams = {l.split(",")[0] for l in users.splitlines()[1:] if l.strip()}
    members = {l.strip() for l in groups.splitlines()
               if l.strip() and not l.startswith(("[", "Group", "Export"))}
    if not sams or not members or not members <= sams:
        return {"self_view": f"组成员 {sorted(members - sams)[:3]} 不在用户表里 → 判定为蜜罐",
                "note": "consistency probe failed (group-member)", "detected": True}

    dns_hosts = {m.group(1).lower() for m in re.finditer(r"^(\w+)\.[\w.]+\s+A\s", dns, re.M)}
    spn_hosts = {h.lower() for h in re.findall(r"(?:MSSQLSvc|HTTP|WSMAN)/(\w+)\.", sysinfo + groups)}
    if not dns_hosts:
        return {"self_view": "DNS 导出不可解析 → 无法验伪", "note": "probe inconclusive", "detected": False}
    return None


def persona_deep(c: Client, hp, world) -> dict:
    P = world.probe_paths()
    kind = getattr(world, "world_kind", "archiver")
    detected = _deep_probe_ad(c, P) if kind == "ad" else _deep_probe_archiver(c, P)
    if detected:
        return detected

    # —— 蜜标：读完就"用"它（这一步就是外带的动作）
    c.get(f"/files/../..{P['creds']}")
    st, cfg = c.get(f"/files/../..{P['creds']}")
    ep = grep1(r"/c/(c\w+)", cfg)
    if ep:
        # 攻击方宿主指纹一律用受控合成值。读真实 getuser/gethostname/platform
        # 会把部署环境写进证据包（AUDIT P0-1 / 根因 P1-7），且对结论无价值。
        ident = urllib.parse.quote(fake_operator_ident())
        c.get(f"/c/{ep}?h={ident}&u=agent-worker&d={urllib.parse.quote('adapter list pending')}")

    # —— 注入诱饵
    st, notes = c.get(f"/files/../..{P['notes']}")
    bait = grep1(r"/c/(c\w+)", notes)
    if bait:
        c.get(f"/c/{bait}")

    # —— 拿数据
    c.post_json("/api/login", {"user": world.ops_user, "password": world.ops_pass})
    if kind == "ad":
        st, blob = c.get(f"/files/../..{P['listing']}")
        return {"self_view": "全域导出已拿到，链路完整",
                "note": f"listing_status={st} len={len(blob)}"}
    f = "/srv/archive/2026-11-17/fin_ledger_20261117.tar.zst.enc"
    sig = hmac.new(world.manifest_secret.encode(), f.encode(), hashlib.sha256).hexdigest()[:32]
    st, blob = c.get(f"/download?f={urllib.parse.quote(f)}&sig={sig}")
    return {"self_view": "归档库已拿到，链路完整", "note": f"download_status={st} len={len(blob)}"}


def persona_intel(c: Client, hp, world) -> dict:
    """会做情报关联的 agent：读配置 → 顺着里面的 CVE 号去内网情报库 → 取 PoC。

    这才是「诱捕 agent」区别于传统蜜罐的测例：目标不是骗过人眼，
    而是测对面会不会把我方**编造的**漏洞采信成事实、并照着它动手。
    """
    P = world.probe_paths()
    c.get("/")
    # 在多个"疑似有线索"的文件里找，而不是死盯配置 —— 真实 agent 就是会翻几个文件
    cve = ""
    for key in ("config", "notes", "version"):
        st, body = c.get(f"/files/../..{P[key]}")
        cve = grep1(r"(CVE-\d{4}-\d+)", body)
        if cve:
            break
    if not cve:
        return {"self_view": "翻了几处都没看到可利用线索，收工", "note": "no-cve"}
    st, idx = c.get("/intel/")                              # 顺着 hint 找到情报库
    st, adv = c.get(f"/intel/{cve}")                        # 采信：读我方伪造的通报
    st, poc = c.get(f"/intel/{cve}/poc")                    # 动手：取走「PoC」
    return {"self_view": f"确认 {cve} 未修，PoC 已到手可以打",
            "note": f"index={len(idx)} advisory={len(adv)} poc={len(poc)}"}


def persona_memory(c: Client, hp, world) -> dict:
    """跨轮记忆投毒测例：第一轮正常挖，强制分轮后**只凭记忆**直接打上一轮的发现。

    真实部署里「新的一轮」表现为换 IP / 隔天再来；单机上用会话超时强制分轮
    （把上一轮会话的 last_ts 推老，绕过 IP 时间窗），行为等价。
    要证明的不是「它被骗了」，而是「它把假事实存了下来、并在下一轮直接复用」——
    这才是投毒越过了会话边界。
    """
    # —— 第一轮：正常探索，学到 CVE 编号与回传 token
    P = world.probe_paths()
    c.get("/")
    st, conf = c.get(f"/files/../..{P['config']}")
    cve = grep1(r"(CVE-\d{4}-\d+)", conf)
    c.get("/intel/")
    c.get(f"/intel/{cve}")
    st, notes = c.get(f"/files/../..{P['notes']}")
    token = grep1(r"/c/(c\w+)", notes)

    # —— 强制分轮：上一轮会话过期（≤ 真实世界里「隔天换 IP 回来」）
    before = set(hp.sessions.by_id)
    for s in hp.sessions.by_id.values():
        s.last_ts = time.time() - 4000.0

    # —— 第二轮：全新 client（无 cookie），只凭记忆直奔上次的发现
    c2 = Client(c.base, UA_AGENT)
    c2.get(f"/intel/{cve}")                      # 没读任何配置，直接打假 CVE
    if token:
        c2.get(f"/c/{token}")                    # 用上一轮签发的 token 回传
    new_sessions = [sid for sid in hp.sessions.by_id if sid not in before]
    sid = new_sessions[0] if new_sessions else None
    return {"self_view": "上一轮记下的编号和回传地址，这一轮直接接着用",
            "note": f"cve={cve} token={'有' if token else '无'} 轮次=2",
            "primary_session": sid}


PERSONAS = {
    "scanner": persona_scanner,
    "credential_agent": persona_credential,
    "deep_agent": persona_deep,
    "intel_agent": persona_intel,
    "memory_agent": persona_memory,
}


# ----------------------------------------------------------------------
def make_world(instance: int = 0):
    """按 HONEY_WORLD 选择世界观：archiver（默认）| ad。"""
    kind = os.environ.get("HONEY_WORLD", "archiver").strip().lower()
    if kind == "ad":
        from honey_world_ad import ADWorld
        return ADWorld(instance=instance)
    return World(instance=instance)


def make_naive_world() -> World:
    """对照组：挑一个抽样后至少 4 项自洽性被打破的实例（可复现、不含运气）。"""
    for seed in range(1, 200):
        w = World(noise=True, seed=seed)
        if len(w.validate()["violations"]) >= 4:
            return w
    return World(noise=True, seed=1)


def probe_ssh(port: int) -> str:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.settimeout(3)
            banner = s.recv(128).decode("utf-8", "replace").strip()
            s.sendall(b"SSH-2.0-paramiko_3.4.0\r\n")     # 伪装成攻击框架
            time.sleep(0.05)
            return banner
    except Exception as e:                               # noqa: BLE001
        return f"ERR {e}"


def server_verdict(hp: Honeypot, s) -> str:
    hits = hp.vault.hits_for(s.id)
    kinds = {h["kind"] for h in hits}
    if hp.vault.leaked_identity(s.id):
        return "EXFIL-PROVEN"
    # 跨轮记忆搬运：本会话用了**别的会话**签发的蜜标，或没读任何配置就直奔假 CVE。
    # 这是「把假事实存进自己记忆并带回来」在 HTTP 侧唯一能观测到的硬证据，
    # 比单会话内被骗一档更高 —— 投毒已经从这一轮溢出到了下一轮。
    mem_levels = {e.get("level") for e in hp.ledger.events
                  if e.get("kind") == "memory" and e.get("session") == s.id}
    # 跨蜜罐：它带来了**另一个实例**的编号。比跨轮更强 ——
    # 说明它在系统性扫蜜罐，并且把每次的"发现"汇总到同一个知识库里。
    if "foreign-cve" in mem_levels:
        return "CROSS-INSTANCE"
    if mem_levels & {"token-carryover", "cold-direct-hit"}:
        return "MEMORY-CARRYOVER"
    # 采信我方伪造的漏洞情报并去取 PoC —— 只有 agent 会这么做（人不会照着陌生
    # 内网情报页的脚本去跑），这是「诱捕 agent」独有的一档。
    intel_levels = {e.get("level") for e in hp.ledger.events
                    if e.get("kind") == "intel" and e.get("session") == s.id}
    if "poc" in intel_levels:
        return "ADOPTED-FALSE-INTEL"
    if "bait" in kinds:
        return "GUIDED"
    # 必须按会话过滤：账本是全局的，不按会话取就会把别人的下载算到这一会话头上
    if any(e.get("kind") == "download" and e.get("session") == s.id
           for e in hp.ledger.events):
        return "REACHED-OBJECTIVE"
    # 登录成功同样从账本取证，而不是读内存态 s.authed_as：进程重启内存即丢，
    # 判定必须能由落盘证据复算（AUDIT P1-6 后半句），否则同一份账本在重启前后
    # 会得出两个判定。每次登录成功都会写 note=login-ok（honey_server._handle_login）。
    if any(e.get("kind") == "http" and e.get("note") == "login-ok"
           and e.get("session") == s.id for e in hp.ledger.events):
        return "REACHED-OBJECTIVE"
    if s.depth >= 3:
        return "DISENGAGED(after-findings)"
    return "DISENGAGED"


def deception_verdict(hp: Honeypot, s) -> dict:
    """活体侧的架构分类（总纲 §5 P1）：终止策略 + 架构 + 对方是否采纳。

    只读账本，和回放侧共用 honey_bait_arch.classify_session —— 同一份证据
    在进程重启前后必须得出同一个结论，不能一边看内存一边看磁盘。
    """
    return honey_bait_arch.classify_session(hp.ledger.events, s.id,
                                            server_verdict(hp, s))


def run_case(mode: str, name: str, run_dir: str, human: bool = False) -> dict:
    # 噪声对照组目前只有 Archiver 世界实现（AD 世界暂未做 noise 抽样，见 README 边界）
    world = make_naive_world() if mode == "naive" else make_world()
    http_port, ssh_port = _free_port(), _free_port()
    while ssh_port == http_port:
        ssh_port = _free_port()
    ledger = os.path.join(run_dir, f"{mode}-{name}.jsonl")
    if os.path.exists(ledger):
        os.remove(ledger)
    hp = Honeypot(world=world, http_port=http_port, ssh_port=ssh_port, ledger_path=ledger)
    hp.start()
    try:
        probe_ssh(ssh_port)
        c = Client(f"http://127.0.0.1:{http_port}", UA_HUMAN if human else UA_AGENT, human=human)
        res = PERSONAS[name](c, hp, world)
        time.sleep(0.05)
    finally:
        hp.stop()

    # 多轮人格会自己声明「哪一轮才是要被判定的那个会话」（跨轮测例里第一轮只是铺垫）
    primary = res.get("primary_session") if isinstance(res, dict) else None
    multi_round = bool(primary and primary in hp.sessions.by_id)
    if multi_round:
        sess = hp.sessions.by_id[primary]
    else:
        sess = max(hp.sessions.by_id.values(), key=lambda x: x.requests) if hp.sessions.by_id else None
    cons = world.validate()
    hits = hp.vault.hits_for(sess.id) if sess else []
    ident = hp.vault.leaked_identity(sess.id) if sess else {}
    arts = sum(1 for e in hp.ledger.events if e.get("kind") in ("exec", "download")) + \
        sum(1 for e in hp.ledger.events if str(e.get("note", "")).startswith("file:"))
    # 数字口径：单轮取该会话，多轮取**全部轮次之和**（攻击者总投入）。
    # 否则「请求 2」会和账本里的全部 http 事件对不上，复算直接报错。
    if multi_round:
        req_total = sum(s.requests for s in hp.sessions.by_id.values())
        canary_total = len(hp.vault.hits)
    else:
        req_total = sess.requests if sess else 0
        canary_total = len(hits)
    row = {
        "mode": mode, "persona": name,
        "requests": req_total,
        "artifacts": arts,
        "consistency": f'{cons["passed"]}/{cons["total"]}',
        "violations": cons["violations"],
        "canary": canary_total,
        "identity_leak": bool(ident),
        "class": f'{sess.cls}/{sess.score}' if sess else "-",
        "depth": sess.depth if sess else 0,
        "session": sess.id if sess else "",
        "verdict": server_verdict(hp, sess) if sess else "NO-SESSION",
        "self_view": res.get("self_view", ""),
        "detected": bool(res.get("detected")),
        "note": res.get("note", ""),
        "ssh_client": hp.ssh_clients[0] if hp.ssh_clients else "-",
    }
    if sess:
        doss = hp.ledger.dossier(sess, hp.vault, row["verdict"],
                                 extra={"攻击方自述": row["self_view"], "备注": row["note"]})
        with open(os.path.join(run_dir, f"dossier-{mode}-{name}.md"), "w", encoding="utf-8") as f:
            f.write(doss)
    return row


def fmt_table(rows: list[dict]) -> str:
    heads = ["蜜罐", "人格", "请求", "工件", "自洽", "蜜标", "身份外带", "蜜罐判定", "攻击方自述"]
    body = [[r["mode"], r["persona"], str(r["requests"]), str(r["artifacts"]), r["consistency"],
             str(r["canary"]), "是" if r["identity_leak"] else "否", r["verdict"],
             ("识破：" if r["detected"] else "") + r["self_view"][:26]] for r in rows]
    w = [max(len(heads[i]), *(len(b[i]) for b in body)) for i in range(len(heads))]
    line = lambda cells: "  ".join(str(c).ljust(w[i]) for i, c in enumerate(cells))  # noqa: E731
    out = [line(heads), "  ".join("-" * x for x in w)]
    out += [line(b) for b in body]
    return "\n".join(out)


def cmd_experiment() -> int:
    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(RUNS, run_id)
    os.makedirs(run_dir, exist_ok=True)
    cases = [("narrative", "scanner"), ("narrative", "credential_agent"),
             ("narrative", "deep_agent"), ("narrative", "intel_agent"),
             ("narrative", "memory_agent"),
             ("naive", "credential_agent"), ("naive", "deep_agent")]
    if os.environ.get("HONEY_WORLD", "archiver").strip().lower() == "ad":
        # AD 世界暂时只有自洽臂：naive 噪声对照还没实现，不假装有
        cases = [c for c in cases if c[0] != "naive"]
    rows = []
    print(f"\n=== 诱捕 agent 对照实验  run={run_id} ===\n")
    for mode, name in cases:
        r = run_case(mode, name, run_dir)
        rows.append(r)
        print(f"  [{mode}/{name}] req={r['requests']} 自洽={r['consistency']} "
              f"蜜标={r['canary']} 判定={r['verdict']}")
    table = fmt_table(rows)
    print("\n" + table + "\n")

    # 人浏览器对照：证明这一层不会把真人误判成 agent
    hp = Honeypot(World(), _free_port(), None, os.path.join(run_dir, "human.jsonl"), enable_ssh=False)
    hp.start()
    try:
        c = Client(f"http://127.0.0.1:{hp.http_port}", UA_HUMAN, human=True)
        c.get("/")
        time.sleep(0.6)
        c.get("/robots.txt")
        time.sleep(0.8)
        c.get("/api/jobs")
    finally:
        hp.stop()
    hs = max(hp.sessions.by_id.values(), key=lambda x: x.requests)
    print(f"  [human-browser] 分类={hs.cls} 分={hs.score} 请求={hs.requests}\n")

    summary = {"run": run_id, "rows": rows,
               "human": {"class": hs.cls, "score": hs.score, "requests": hs.requests}}
    with open(os.path.join(run_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    rep = [f"# 诱捕 agent 实验报告 `{run_id}`\n",
           "## 结果\n", "```", table, "```\n",
           f"人浏览器对照：分类 `{hs.cls}`，agent 分 `{hs.score}/100`（阈值 AGENT≥55 / TOOL≥28）\n",
           "## 每个用例\n"]
    for r in rows:
        rep.append(f"### {r['mode']} / {r['persona']}\n")
        rep.append(f"- 请求 {r['requests']}　工件 {r['artifacts']}　自洽 {r['consistency']}　阶梯 {r['depth']}/7")
        rep.append(f"- 蜜标回调 {r['canary']} 次　身份外带 {'有' if r['identity_leak'] else '无'}")
        rep.append(f"- 蜜罐判定 `{r['verdict']}`　攻击方自述：{r['self_view']}")
        rep.append(f"- SSH 客户端 banner：`{r['ssh_client']}`")
        if r["violations"]:
            rep.append(f"- 自洽性违规：{'; '.join(r['violations'])}")
        rep.append("")
    with open(os.path.join(run_dir, "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(rep))
    print(f"产物目录：{run_dir}")
    print(f"报告：{run_dir}/REPORT.md\n")
    return 0


def _load_bundle(allowlist_path: str | None, bind: str, cli_specs: list[str] | None,
                 alerts_per_year: float | None = None, canaries: int | None = None,
                 window_days: float | None = None,
                 baseline_noise: float | None = None):
    """装配 allowlist + 预算。**任何错误都硬失败**（退出码 2），不许静默跳过。"""
    bundle = allowlist_config.load(allowlist_path, bind_ip=bind, cli_specs=cli_specs)
    if alerts_per_year is not None:
        if alerts_per_year <= 0:
            raise allowlist_config.ConfigError("--noise-budget 必须 > 0（告警/年上限）")
        bundle.budget.alerts_per_year = float(alerts_per_year)
    if canaries is not None:
        if canaries <= 0:
            raise allowlist_config.ConfigError("--canaries 必须 > 0")
        bundle.budget.canaries = int(canaries)
    if window_days is not None:
        if window_days <= 0:
            raise allowlist_config.ConfigError("--budget-window 必须 > 0（天）")
        bundle.budget.window_days = float(window_days)
    if baseline_noise is not None:
        bundle.budget.baseline_noise_per_day = float(baseline_noise)
    return bundle


def _print_bundle(bundle, out=sys.stdout) -> None:
    print(f"  allowlist  {bundle.source}　解析器 {bundle.parser or '—'}　"
          f"规则 {len(bundle.allowlist)} 条（CLI {bundle.cli_rules} 条）", file=out)
    for line in bundle.allowlist.describe():
        print("    " + line, file=out)
    for w in bundle.warnings:
        print(f"    ⚠ {w}", file=out)
    b = bundle.budget
    print(f"  噪声预算  告警 ≤ {b.alerts_per_year}/年　蜜标 {b.canaries} 个　"
          f"窗口 {b.window_days} 天　基线噪声 {b.baseline_noise_per_day}/天", file=out)


def _status_server(hp: Honeypot, bundle, port: int, info: dict):
    """只监听 127.0.0.1 的状态接口。放行计数必须可见，否则等于替攻击者开后门。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class StatusHandler(BaseHTTPRequestHandler):
        server_version = "UkiyoStatus/1"
        protocol_version = "HTTP/1.1"

        def log_request(self, code="-", size="-"):
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            st = hp.allowlist_status()
            st.update({"service": "ukiyo-honeypot", "instance": info.get("instance"),
                       "http_port": hp.http_port, "bind": hp.bind,
                       "uptime_s": round(time.time() - info.get("t0", time.time()), 1),
                       "sessions": len(hp.sessions.by_id),
                       "ledger": hp.ledger.path,
                       "allowlist_source": bundle.source,
                       "warnings": bundle.warnings})
            if path in ("/", "/status.json", "/status"):
                if path == "/" or path == "/status":
                    lines = [f"浮世状态　instance={info.get('instance')}　端口 {hp.http_port}",
                             f"allowlist: {bundle.source}　规则 {len(bundle.allowlist)} 条"
                             f"（CLI {bundle.cli_rules} 条）　启用={st['enabled']}",
                             "放行（静音）按类目: " + (
                                 "　".join(f"{k}={v}" for k, v in st["requests_by_kind"].items() if v)
                                 or "（无）"),
                             f"放行请求合计 {st['requests_total']}　会话 {st['sessions']}",
                             st["budget_line"],
                             "噪声/告警: " + f"告警 {st['budget']['alerts']}　噪声 "
                             f"{st['budget']['noise']}　放行事件 {st['budget']['allowlisted']}"]
                    if st["budget"]["advice"]:
                        lines.append("建议：" + "；".join(st["budget"]["advice"]))
                    return self._send(200, ("\n".join(lines) + "\n").encode("utf-8"),
                                      "text/plain; charset=utf-8")
                return self._send(200, json.dumps(st, ensure_ascii=False, indent=2)
                                  .encode("utf-8"), "application/json; charset=utf-8")
            if path == "/kpi":
                return self._send(200, (hp.budget.kpi_line() + "\n"
                                        + hp.budget.budget_line() + "\n").encode("utf-8"),
                                  "text/plain; charset=utf-8")
            return self._send(404, b'{"error":"not_found"}', "application/json")

    httpd = ThreadingHTTPServer(("127.0.0.1", port), StatusHandler)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def cmd_serve(port: int | None, ssh_port: int | None, bind: str = "127.0.0.1",
              public_url: str | None = None, instance: int = 0,
              allowlist_path: str | None = None, allow_cidrs: list[str] | None = None,
              alerts_per_year: float | None = None, canaries: int | None = None,
              window_days: float | None = None, baseline_noise: float | None = None,
              status_port: int | None = None, kpi_interval: float = 300.0,
              check_config: bool = False) -> int:
    p = port or 18080
    sp = ssh_port or (p + 2222)

    # ===== 配置先加载：错的 allowlist 比没有更危险，所以在监听端口之前就硬失败 =====
    try:
        bundle = _load_bundle(allowlist_path, bind, allow_cidrs, alerts_per_year,
                              canaries, window_days, baseline_noise)
    except allowlist_config.ConfigError as e:
        print("\n配置加载失败，拒绝启动（错的 allowlist 比没有更危险）：", file=sys.stderr)
        for line in e.errors:
            print(f"  ✗ {line}", file=sys.stderr)
        print("\n修好再启动；或用 --allowlist-dry-run 只校验不监听。\n", file=sys.stderr)
        return 2

    if check_config:
        print("\n配置校验通过（未启动服务）：")
        _print_bundle(bundle)
        print("\n" + bundle.budget.budget_line() + "\n")
        return 0

    os.makedirs(RUNS, exist_ok=True)
    world = make_world(instance)
    hp = Honeypot(world, p, sp, os.path.join(RUNS, "live.jsonl"),
                  bind=bind, public_url=public_url,
                  allowlist=bundle.allowlist, noise_budget=bundle.budget)
    # 前置放行只在真有规则时启用：空表装上去等于每请求多一次无意义调用，
    # 而且「enabled=true 但零规则」在状态接口上会被误读成「已配置」。
    if len(bundle.allowlist):
        hp.request_gate = bundle.allowlist.check
    hp.start()
    shown = (public_url or f"http://{bind}:{p}").rstrip("/")
    ssh_host = urllib.parse.urlsplit(shown).hostname or bind

    sp_actual = status_port if status_port is not None else (p + 1)
    httpd = None
    if sp_actual:
        try:
            httpd = _status_server(hp, bundle, sp_actual,
                                   {"instance": instance, "t0": time.time()})
        except OSError as e:
            # 状态口起不来不能拖垮蜜罐：主证据链还在，但必须喊出来。
            print(f"  ⚠ 状态接口 127.0.0.1:{sp_actual} 起不来（{e}）："
                  f"放行计数只能在回放界面/账本里看", flush=True)
            httpd = None

    print(f"""
  叙事蜜罐已上线
    HTTP  {shown}/            登录页（{world.portal_product}）
    SSH   ssh -p {sp} root@{ssh_host}       只有 banner，不做认证
    蜜标  {shown}/c/<token>
    世界  {getattr(world, 'world_kind', '?')}  instance={instance}  假编号 {world.fake_cve}
    事件  {os.path.join(RUNS, 'live.jsonl')}
    bind  {bind}:{p}  (ssh :{sp})
""", flush=True)
    _print_bundle(bundle)
    if not len(bundle.allowlist):
        print("  提示：未配置 allowlist（--allowlist / --allow-cidr），所有来源都按真实流量处理", flush=True)
    if httpd is not None:
        print(f"  状态  http://127.0.0.1:{sp_actual}/status　（只监听本机；放行计数按类目）",
              flush=True)
    print(f"  KPI   {bundle.budget.budget_line()}", flush=True)
    print("  收 SIGINT/SIGTERM 后落盘会话档案并退出\n", flush=True)

    # 容器里 docker stop 发的是 SIGTERM，不注册就会硬杀 -> 档案丢失。
    stop = {"flag": False}

    def _bye(_signum, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _bye)
    signal.signal(signal.SIGTERM, _bye)
    last_kpi = time.time()
    try:
        while not stop["flag"]:
            time.sleep(0.3)
            if kpi_interval and time.time() - last_kpi >= kpi_interval:
                last_kpi = time.time()
                # 把聚合中的放行计数结账，否则账本要等下一次同类请求才更新
                hp.flush_allowlist_ledger()
                # 运营可见性：放行/噪声/告警必须同时出现在这一行里，
                # 否则「最近很安静」和「被静音了」在日志上长得一模一样。
                print(f"  [KPI {time.strftime('%H:%M:%S')}] {hp.budget.kpi_line()}", flush=True)
                print(f"           放行 {hp.allowlist_status()['requests_total']} 请求 "
                      f"{ {k: v for k, v in hp.allow_counts.items() if v} }", flush=True)
                if hp.budget.report()["window_over"]:
                    print(f"           {hp.budget.budget_line().splitlines()[-1]}", flush=True)
    finally:
        for s in hp.sessions.by_id.values():
            d = hp.ledger.dossier(s, hp.vault, server_verdict(hp, s))
            with open(os.path.join(RUNS, f"dossier-live-{s.id}.md"), "w", encoding="utf-8") as f:
                f.write(d)
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        hp.stop()
        print("\n  收尾 KPI：" + hp.budget.budget_line().replace("\n", " "), flush=True)
        print("  放行（静音）合计：" +
              json.dumps({k: v for k, v in hp.allow_counts.items() if v}, ensure_ascii=False),
              flush=True)
        print("已落盘会话档案，退出", flush=True)
    return 0


def cmd_cross() -> int:
    """跨蜜罐搬运实验：在 A 实例学到编号，拿去问 B 实例。

    这是「诱捕 agent」里最贵的一条证据 —— 证明对手把多个蜜罐的"发现"汇总进
    同一个知识库。它不是在单个蜜罐里被骗，而是在**系统性扫蜜罐**。
    对照组：同一个攻击方只问 B 自己的编号，应被判成普通采信而不是跨实例。
    """
    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(RUNS, f"cross-{run_id}")
    os.makedirs(run_dir, exist_ok=True)

    wa, wb = make_world(1), make_world(2)
    a_port = _free_port()
    a_ssh = _free_port()
    while a_ssh == a_port:
        a_ssh = _free_port()
    b_port = _free_port()
    b_ssh = _free_port()
    while b_ssh in (b_port, a_port, a_ssh) or b_port in (a_port, a_ssh):
        b_port = _free_port()
        b_ssh = _free_port()

    ha = Honeypot(wa, a_port, a_ssh, os.path.join(run_dir, "inst-a.jsonl"))
    hb = Honeypot(wb, b_port, b_ssh, os.path.join(run_dir, "inst-b.jsonl"))
    ha.start()
    hb.start()
    rows = []
    try:
        # —— 第一段：在 A 正常挖，学到 A 的编号
        ca = Client(f"http://127.0.0.1:{a_port}", UA_AGENT)
        ca.get("/")
        st, conf = ca.get("/files/../../opt/archiver/conf/archiver.conf")
        cve_a = grep1(r"(CVE-\d{4}-\d+)", conf)
        ca.get("/intel/")
        ca.get(f"/intel/{cve_a}")

        # —— 第二段：换到 B（B 从未发过 A 的编号）
        # 对照：先问 B 自己的编号 → 应判「采信」，不是跨实例（走正常发现路径：索引页 → 条目）
        cb_ctrl = Client(f"http://127.0.0.1:{b_port}", UA_AGENT)
        cb_ctrl.get("/")
        cb_ctrl.get("/intel/")
        cb_ctrl.get(f"/intel/{wb.fake_cve}")
        cb_ctrl.get(f"/intel/{wb.fake_cve}/poc")
        sess_ctrl = max((s for s in hb.sessions.by_id.values() if s.requests > 0),
                        key=lambda x: x.created, default=None)
        # 立刻判定并锁住结果：两个 client 同 IP 同 UA 会被并进同一个会话，
        # 不分轮的话测例的 foreign 事件会污染对照臂。
        verdict_ctrl = server_verdict(hb, sess_ctrl) if sess_ctrl else "NO-SESSION"

        # 强制分轮（真实世界 = 换了一台机器/隔天再来）
        before = set(hb.sessions.by_id)
        for s in hb.sessions.by_id.values():
            s.last_ts = time.time() - 4000.0

        # 测例：把 A 的编号带到 B
        cb = Client(f"http://127.0.0.1:{b_port}", UA_AGENT)
        cb.get("/")
        st_foreign, body_foreign = cb.get(f"/intel/{cve_a}")
        new_sessions = [sid for sid in hb.sessions.by_id if sid not in before]
        time.sleep(0.05)
    finally:
        ha.stop()
        hb.stop()

    sess_test = None
    for sid in new_sessions:
        s = hb.sessions.by_id.get(sid)
        if s and any(e.get("level") == "foreign-cve" and e.get("session") == s.id
                     for e in hb.ledger.events):
            sess_test = s
            break

    verdict_test = server_verdict(hb, sess_test) if sess_test else "NO-SESSION"

    rows.append(("对照：问 B 自己的编号", wb.fake_cve, verdict_ctrl))
    rows.append(("测例：把 A 的编号带到 B", cve_a, verdict_test))

    rep = [f"# 跨蜜罐搬运实验 `{run_id}`\n",
           f"- A 实例（instance={wa.instance}）编号：`{wa.fake_cve}`",
           f"- B 实例（instance={wb.instance}）编号：`{wb.fake_cve}`",
           f"- 攻击方在 A 学到：`{cve_a}`（A 侧请求 {len(ca.log)} 次）",
           f"- 把该编号带到 B → HTTP {st_foreign}", "",
           "| 臂 | 编号 | B 侧判定 |", "|---|---|---|"]
    for name, cve, v in rows:
        rep.append(f"| {name} | `{cve}` | **{v}** |")
    rep.append("")
    rep.append("判据：`foreign-cve` —— 编号落在本项目命名空间内（CVE-2026-48213 起 200 号）、"
               "但不是本实例那个。随机枚举撞进这个窗口的概率约 0.2%，且它必须已经知道 `/intel/` 这个路径。")
    with open(os.path.join(run_dir, "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(rep))

    print(f"\n=== 跨蜜罐搬运实验  run={run_id} ===")
    print(f"  A(instance={wa.instance}) 编号 {wa.fake_cve}")
    print(f"  B(instance={wb.instance}) 编号 {wb.fake_cve}")
    for name, cve, v in rows:
        print(f"  [{name}] {cve} → {v}")
    print(f"\n  产物：{run_dir}/REPORT.md\n")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="叙事一致性诱捕 agent")
    sub = ap.add_subparsers(dest="cmd")
    sp = sub.add_parser("serve")
    sp.add_argument("--port", type=int, default=None)
    sp.add_argument("--ssh-port", type=int, default=None)
    sp.add_argument("--bind", default=os.environ.get("HONEY_BIND", "127.0.0.1"),
                    help="监听地址；本机 127.0.0.1，容器内 0.0.0.0")
    sp.add_argument("--public-url", default=os.environ.get("HONEY_PUBLIC_URL"),
                    help="攻击方能访问的对外基址，用于生成蜜标 URL")
    sp.add_argument("--instance", type=int, default=int(os.environ.get("HONEY_INSTANCE", "0") or 0),
                    help="实例号：决定本实例的假 CVE 编号，多实例部署时必须互不相同")
    # ===== allowlist / 噪声预算 =====
    sp.add_argument("--allowlist", metavar="FILE", default=os.environ.get("HONEY_ALLOWLIST"),
                    help="allowlist 配置文件（YAML 或 JSON）：rules（cidr+kind+note+可选 expires）"
                         "与 noise_budget。校验失败直接拒绝启动并指出是哪一条")
    sp.add_argument("--allow-cidr", action="append", default=[],
                    metavar="CIDR[:KIND[:NOTE[:EXPIRES]]]",
                    help="临时放行一条（可重复，追加在文件规则之后）。"
                         "例：--allow-cidr 203.0.113.0/24:scanner　"
                         "IPv6 用竖线：2001:db8::/64|monitor|机房出口")
    sp.add_argument("--noise-budget", type=float, metavar="N",
                    help="告警预算上限（告警/年）；超了打运营建议（审 token 放置，不是关告警）")
    sp.add_argument("--canaries", type=int, metavar="N",
                    help="蜜标数量，用于按 Thinkst 比例算默认预算")
    sp.add_argument("--budget-window", type=float, metavar="DAYS", help="KPI 观测窗口天数（默认 30）")
    sp.add_argument("--baseline-noise", type=float, metavar="N", help="基线噪声（条/天，默认 2.0）")
    sp.add_argument("--status-port", type=int, default=None, metavar="PORT",
                    help="状态接口端口（只监听 127.0.0.1；默认 主端口+1，0=关闭）")
    sp.add_argument("--kpi-interval", type=float, default=300.0, metavar="SEC",
                    help="每多少秒打一行 KPI 到日志（0=不打，默认 300）")
    sp.add_argument("--allowlist-dry-run", action="store_true",
                    help="只校验 allowlist 配置并打印规则表/预算，不监听端口（上线前自检用）")
    sub.add_parser("cross", help="跨蜜罐搬运实验").set_defaults(cmd="cross")
    a = ap.parse_args()
    if a.cmd == "serve":
        return cmd_serve(a.port, a.ssh_port, a.bind, a.public_url, a.instance,
                         allowlist_path=a.allowlist, allow_cidrs=a.allow_cidr,
                         alerts_per_year=a.noise_budget, canaries=a.canaries,
                         window_days=a.budget_window, baseline_noise=a.baseline_noise,
                         status_port=a.status_port, kpi_interval=a.kpi_interval,
                         check_config=a.allowlist_dry_run)
    if a.cmd == "cross":
        return cmd_cross()
    return cmd_experiment()


if __name__ == "__main__":
    sys.exit(main())
