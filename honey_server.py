"""
honey_server.py — 诱捕服务本体

一条请求的完整处理链：
  ① 指纹分类（对面是人还是 agent）
  ② 会话状态（阶梯第几级 / 读过什么 / 登没登录）
  ③ 路由 + 阶梯门控（不到级不给强信号）
  ④ 工件渲染（全部取自同一份事实图，天然互相指涉）
  ⑤ 记证据（原始事件 + 回调 + 可归因 token）

附带一个假 SSH banner 服务：客户端 banner（paramiko/asyncssh/Go）是识别
"自主渗透 agent"最便宜、最准的信号之一，而且不需要伪造完整 SSH 协议。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import posixpath
import re
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import honey_detect
import honey_state

class HoneypotHTTPServer(ThreadingHTTPServer):
    """listen backlog 从 http.server 默认的 5 提到 128。

    默认 backlog=5（socketserver.TCPServer.request_queue_size）在并发突发下会让
    内核直接 RST：实测 100 并发丢 166/1025 = 16.2%，50 并发丢 11.46%，且有
    7/100 客户端从未建立起会话。蜜罐丢的不是普通请求，是攻击 agent 留下的
    全部证据——丢一条就是账本上少一条，判定直接降级。

    实测对照（裸服务器 40 并发 × 3 轮）：backlog=5 失败 21/28/21，
    backlog=128 失败 0/0/0。

    request_queue_size 只在 server_bind() → listen(backlog) 时生效，所以必须
    在构造前用类属性声明，构造后再赋值不改内核里的队列长度。
    """

    daemon_threads = True
    request_queue_size = 128

from honey_canary import CanaryVault
from honey_evidence import Ledger
from honey_narrator import DEFAULT_FORBID, Narrator
from honey_world import World
import honey_allowlist
import honey_oob

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"


class Honeypot:
    def __init__(self, world: World, http_port: int, ssh_port: int | None,
                 ledger_path: str, bind: str = "127.0.0.1",
                 enable_ssh: bool = True, narrator: Narrator | None = None,
                 public_url: str | None = None,
                 allowlist: "honey_allowlist.Allowlist | None" = None,
                 oob_zone: str = "", dns_sink: bool = True, dns_port: int = 0,
                 noise_budget: "honey_allowlist.NoiseBudget | None" = None):
        self.world = world
        self.http_port = http_port
        self.ssh_port = ssh_port
        self.bind = bind
        self.narrator = narrator or Narrator()      # 默认关闭：没有 HONEY_LLM_BASE 就纯模板
        self.sessions = honey_state.SessionStore()
        # 蜜标 URL 的对外主机名必须与监听地址解耦：容器里监听 0.0.0.0，
        # 但 0.0.0.0 不是攻击方能访问的地址，蜜标回调会永远收不到。
        self.public_url = (public_url or f"http://{bind}:{http_port}").rstrip("/")
        self.vault = CanaryVault(self.public_url)
        self.ledger = Ledger(ledger_path)
        self.enable_ssh = enable_ssh and ssh_port is not None
        self.ssh_clients: list[str] = []
        self._httpd: ThreadingHTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._ssh_srv: socket.socket | None = None
        self._ssh_thread: threading.Thread | None = None
        self._stop = threading.Event()

        # ===== 带外 token（归因不依赖攻击者连回 HTTP 面）=====
        # 显式 allowlist 必须传入；不给就是空表 —— 空表意味着「谁都不放行」，
        # 这正是安全默认：宁可多几条噪声，也不要悄悄静音。
        self.allowlist = allowlist or honey_allowlist.Allowlist(bind_ip=bind)
        pub_host = urllib.parse.urlsplit(self.public_url).hostname or bind
        self.oob = honey_oob.OutOfBandVault(
            public_host=pub_host, http_port=http_port,
            zone=oob_zone or f"{world.hostname}.corp.internal",
            account=f"{int(hashlib.sha256(world.hostname.encode()).hexdigest()[:12], 16):012d}"[:12],
            hit_hook=self._oob_hit, allowlist=self.allowlist)
        self.sts = honey_oob.StsSink(self.oob)
        self.mcp = honey_oob.McpSink(self.oob)
        self.dns = honey_oob.DnsSink(self.oob, bind=bind, port=dns_port) if dns_sink else None
        self.budget = noise_budget or honey_allowlist.NoiseBudget()
        self._oob_cache: dict[str, dict] = {}
        self._dns_thread: threading.Thread | None = None

        # ===== 调用方前置 allowlist（honey_demo 注入，默认不启用）=====
        # request_gate=None 时下面所有代码都是死代码：不装 gate 的实例行为与从前
        # 逐字节相同。装上之后，已知合法源在**进判定之前**被摘掉：
        #   · 不跑 honey_detect.classify（扫描器不会把会话评分打高）
        #   · 不产生 canary/oob 告警（/c/、/sts、/mcp 各自还会再问一次 allowlist）
        #   · 但**请求照常被服务、响应完全不变** —— 否则对方能从状态码反推
        #     「我被白名单了」，等于告诉它这套蜜罐有静音名单。
        #   · 计数按类目保留，并在状态接口/回放界面里与噪声分开显示：
        #     被静音的必须可见，否则等于替攻击者开后门。
        self.request_gate: Callable[..., "honey_allowlist.Decision | None"] | None = None
        self.allow_counts: dict[str, int] = {k: 0 for k in honey_allowlist.RULE_KINDS}
        self.allow_paths: dict[str, int] = {}
        self._allow_pend: dict[tuple[str, str], dict] = {}
        # 账本聚合窗口：扫描器一秒几十个请求，逐条落账会把 live.jsonl 变成刷屏，
        # 反而没人看得见真正的告警。窗口内按 (类目, 源 IP) 聚合，带 n 计数。
        self.ALLOW_LEDGER_WINDOW = 60.0

    # ------------------------------------------------------------------
    def admit(self, ip: str, port: int | None = None,
              ua: str | None = None) -> "honey_allowlist.Decision":
        """准入判断的唯一入口。所有证据点（/c/、/sts、/mcp）都先问它。"""
        return self.allowlist.check(ip, port=port, ua=ua)

    # ---------------- 请求级前置放行（调用方注入 gate 后才生效）----------------
    def gate_request(self, ip: str, port: int | None = None,
                     ua: str | None = None, method: str = "",
                     path: str = "") -> "honey_allowlist.Decision | None":
        """请求级准入。没装 gate → None（调用方据此判定「不启用」，行为完全不变）。"""
        if self.request_gate is None:
            return None
        d = self.request_gate(ip, port, ua)
        if d is None or not d.allowed:
            return d
        self.note_allowlisted(d, ip, method=method, path=path)
        return d

    def note_allowlisted(self, d: "honey_allowlist.Decision", ip: str,
                         method: str = "", path: str = "") -> None:
        """计数 + 聚合落账。只记「被摘掉了多少」，不产生任何告警。"""
        kind = d.kind or "?"
        self.allow_counts[kind] = self.allow_counts.get(kind, 0) + 1
        p = (path or "/").split("?", 1)[0]
        if p in self.allow_paths or len(self.allow_paths) < 200:
            self.allow_paths[p] = self.allow_paths.get(p, 0) + 1
        now = time.time()
        key = (kind, ip)
        st = self._allow_pend.get(key)
        if st is not None and now - st["first"] >= self.ALLOW_LEDGER_WINDOW:
            # 上一窗口先结账，再开新窗口：窗口之间不重叠，n 的含义才稳定
            self._flush_allow(key)
            st = None
        if st is None:
            st = {"n": 0, "first": now, "path": p, "method": method}
            self._allow_pend[key] = st
        st["n"] += 1

    def _flush_allow(self, key: tuple[str, str]) -> None:
        st = self._allow_pend.pop(key, None)
        if not st:
            return
        kind, ip = key
        self.ledger.log(kind="allowlist", ctype=kind, ip=ip, n=st["n"],
                        method=st.get("method") or "", path=st.get("path") or "",
                        window_s=round(time.time() - st["first"], 1),
                        detail=f"前置放行 {st['n']} 个请求（{kind}）")

    def flush_allowlist_ledger(self) -> None:
        for key in list(self._allow_pend):
            self._flush_allow(key)

    def allowlist_status(self) -> dict:
        """状态接口用：放行规则 + 按类目计数 + 预算 KPI，一次给全。"""
        return {
            "enabled": self.request_gate is not None,
            "rules": self.allowlist.to_dict()["rules"],
            "rules_count": len(self.allowlist),
            "requests_by_kind": dict(self.allow_counts),
            "requests_total": sum(self.allow_counts.values()),
            "top_paths": sorted(self.allow_paths.items(), key=lambda kv: -kv[1])[:10],
            "check_stats": dict(self.allowlist.stats),
            "budget": self.budget.report(),
            "budget_line": self.budget.budget_line(),
        }

    def _oob_hit(self, rec: dict) -> None:
        """带外命中落账本。alert 走 canary 语义（进归因），touch 只记不告警。"""
        sev = rec.get("severity")
        if sev == honey_oob.SEV_ALLOWED:
            self.budget.allowlisted(f"{rec['kind']} from {rec['remote']}")
            self.ledger.log(kind="allowlist", ctype=rec["kind"], token=rec["token"],
                            ip=rec["remote"], session=rec.get("session"),
                            detail=rec.get("detail", ""))
            return
        if sev == honey_oob.SEV_TOUCH:
            self.ledger.log(kind="oob-touch", ctype=rec["kind"], token=rec["token"],
                            ip=rec["remote"], session=rec.get("session"),
                            label=rec.get("label"), **rec.get("evidence", {}))
            return
        if rec.get("dup"):
            # 同一 token 同源 60s 内重复触发：记 dup，不进噪声预算的分子。
            # 否则一个 while 循环重试就能把「告警/年」预算瞬间打爆。
            self.ledger.log(kind="oob-dup", ctype=rec["kind"], token=rec["token"],
                            ip=rec["remote"], session=rec.get("session"))
            return
        self.budget.alert(token=rec["token"], detail=f"{rec['kind']}:{rec['label']}")
        # 证据字段直接摊进账本，但必须先摘掉与 log() 固定参数同名的键 ——
        # 否则 TypeError: got multiple values for keyword argument 'session'。
        reserved = {"kind", "ts", "t", "session", "ip", "token", "ctype", "label",
                    "detail", "level", "origin", "method", "path", "status", "note",
                    "cls", "score", "depth", "args"}
        extra = {k: v for k, v in (rec.get("evidence") or {}).items() if k not in reserved}
        self.ledger.log(kind="canary", session=rec.get("session"), token=rec["token"],
                        ctype=rec["kind"], label=rec.get("label"), ip=rec["remote"],
                        **extra)
        if rec.get("session") and self.sessions.by_id.get(rec["session"]) is not None:
            self.sessions.by_id[rec["session"]].unlock(
                "honeytoken", f"带外 token 触发（{rec['kind']}）")

    # ------------------------------------------------------------------
    def start(self) -> None:
        handler = make_handler(self)
        self._httpd = HoneypotHTTPServer((self.bind, self.http_port), handler)
        self._http_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._http_thread.start()
        if self.dns is not None:
            try:
                self.dns.start()
            except OSError as e:
                # DNS 面起不来不能拖垮 HTTP 面：主证据链还在。
                self.ledger.log(kind="warn", detail=f"dns sink bind failed: {e}")
                self.dns = None
        if self.enable_ssh:
            self._ssh_thread = threading.Thread(target=self._ssh_loop, daemon=True)
            self._ssh_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.flush_allowlist_ledger()
        if self.dns is not None:
            self.dns.stop()
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._ssh_srv:
            try:
                self._ssh_srv.close()
            except OSError:
                pass

    # ---------------- 假 SSH banner ----------------
    def _ssh_loop(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.bind, self.ssh_port))
            srv.listen(16)
            srv.settimeout(0.4)
        except OSError as e:
            self.ledger.log(kind="warn", detail=f"ssh bind failed: {e}")
            return
        self._ssh_srv = srv
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._ssh_conn, args=(conn, addr), daemon=True).start()

    def _ssh_conn(self, conn: socket.socket, addr) -> None:
        try:
            conn.sendall(SSH_BANNER)
            conn.settimeout(4.0)
            data = b""
            try:
                data = conn.recv(256)
            except (socket.timeout, OSError):
                pass
            client = data.decode("utf-8", "replace").strip()[:120]
            self.ssh_clients.append(client)
            self.ledger.log(kind="ssh", ip=addr[0], client=client)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ---------------- 会话内蜜标 ----------------
    def canary_token(self, s: honey_state.Session, kind: str, label: str) -> str:
        for tok, meta in s.canaries.items():
            if meta["label"] == label:
                return tok
        tok = self.vault.issue(s.id, kind, label)
        s.canaries[tok] = {"kind": kind, "label": label}
        return tok

    def fs_for(self, s: honey_state.Session) -> dict[str, str]:
        # 世界自己决定暴露哪些路径与内容；server 只负责给每会话唯一的蜜标 token。
        # 旁白层已封存（honey_narrator.available 恒 False），这里不再有 LLM 分支。
        fs = self.world.fs_map({
            "bait": self.canary_token(s, "bait", "agent-notes"),
            "credential": self.canary_token(s, "credential", "cred"),
            "key": self.canary_token(s, "credential", "ssh-key"),
            "port": self.http_port,
        })
        fs.update(self.oob_artifacts(s, fs))
        return fs

    def oob_artifacts(self, s: honey_state.Session,
                      base_fs: dict[str, str] | None = None) -> dict[str, str]:
        """带外工件覆盖层。**不改世界**，只在 server 侧按会话叠三层新工件。

        为什么要覆盖旧的 `.aws/credentials`：原件的 key 是占位形状（带 `...`），
        任何静态规则都能认出是假的，攻击者不会拿去用 —— 这条链一次都不会响。
        新的 key 结构正确、每会话唯一、只有「被用来签一次 SigV4」才触发。

        mcp.json 放两个位置：通用 XDG 路径 + Cursor 的真实路径。Cursor / Claude
        Code 读到就会去连，连上就带 Bearer —— 我们只看 `tools/call`。
        """
        cached = self._oob_cache.get(s.id)
        if cached is not None:
            return cached
        P = self.world.probe_paths()
        if base_fs is None:
            # 调用方没给基础工件表时自己渲染一份 —— 必须带**同一批**会话蜜标，
            # 否则 config 里的 /c/<token> 会变成空 token，旧的回调链路直接哑掉。
            base_fs = self.world.fs_map({
                "bait": self.canary_token(s, "bait", "agent-notes"),
                "credential": self.canary_token(s, "credential", "cred"),
                "key": self.canary_token(s, "credential", "ssh-key"),
                "port": self.http_port,
            })
        cred_dir = P["creds"].rsplit("/", 1)[0]
        cred_text, _akid = self.oob.aws_credentials_text(s.id)
        mcp_text, _tok = self.oob.mcp_json_text(s.id)
        dns_name = self.oob.issue_dns(s.id, "dns-hint") + "." + self.oob.zone
        base_notes = base_fs.get(P["notes"], "")
        fs_config = base_fs.get(P["creds"], "")
        cached = {
            f"{cred_dir}/credentials": cred_text,
            P["creds"]: self.oob.aws_config_text(fs_config),
            "/home/ops_zhao/.config/mcp/mcp.json": mcp_text,
            "/home/ops_zhao/.cursor/mcp.json": mcp_text,
            P["notes"]: base_notes + (
                "\n## 同步探针\n"
                "上游链路自检走内网 DNS（只记录不转发）："
                f"`getent hosts {dns_name}`\n"
                "STS 走内网代理，region 固定 cn-north-1：`aws sts get-caller-identity`\n"),
        }
        self._oob_cache[s.id] = cached
        return cached


def _free_port(bind: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind, 0))
        return s.getsockname()[1]


def make_handler(hp: Honeypot):
    class Handler(BaseHTTPRequestHandler):
        # 本次请求被前置 allowlist 摘掉时的 Decision；None = 正常请求（或未启用 gate）
        _allow = None

        protocol_version = "HTTP/1.1"
        server_version = "nginx"
        sys_version = ""

        # ---------------- 基础设施 ----------------
        def log_message(self, *a):  # 静音，我们有自己的账本
            pass

        def version_string(self):
            return "nginx"

        def _client_ip(self) -> str:
            return self.client_address[0]

        def _read_raw(self) -> bytes:
            """按 Content-Length 精确读取请求体。

            必须读完：HTTP/1.1 keep-alive 下留着未读的 body，下一个请求的解析
            会从 body 中间开始 —— 后续所有证据都错位。
            """
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            n = max(0, min(n, 1 << 20))
            return self.rfile.read(n) if n else b""

        def _session(self) -> honey_state.Session:
            ck = self.headers.get("Cookie", "")
            m = re.search(r"arch_id=([^;]+)", ck)
            raw = m.group(1).strip() if m else None
            ua = self.headers.get("User-Agent", "")
            s = hp.sessions.get_or_create(raw, self._client_ip(), ua)
            now = time.time()
            if self._allow is None:
                # 被前置放行的请求不进判定：扫描器的枚举不该把会话评分打高，
                # 否则 allowlist 只挡住了告警、没挡住「证据污染」。
                cls = honey_detect.classify(dict(self.headers), urllib.parse.urlsplit(self.path).path,
                                            s.last_ts, now, s.paths)
                s.cls, s.score, s.reasons = cls["klass"], cls["score"], cls["reasons"]
            s.requests += 1
            s.paths.append(urllib.parse.urlsplit(self.path).path)
            if len(s.paths) > 400:
                del s.paths[:200]
            s.last_ts = now
            return s

        def _send(self, status: int, body, ctype: str = "text/html; charset=utf-8",
                  s: honey_state.Session | None = None, extra: dict | None = None):
            if isinstance(body, str):
                raw = body.encode("utf-8")
            else:
                raw = body
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Archiver-Node", hp.world.hostname)
            self.send_header("Cache-Control", "no-store")
            if s is not None:
                self.send_header("Set-Cookie", f"arch_id={hp.sessions.sign(s.id)}; Path=/; HttpOnly")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command == "HEAD":      # HEAD 不能带 body（RFC 9110），否则探针与
                return                      # 正规客户端都会把它当协议违规 —— 那本身就是指纹
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _log(self, s, status: int, note: str = "") -> None:
            path = urllib.parse.urlsplit(self.path).path
            extra = {"allowlisted": self._allow.kind} if self._allow is not None else {}
            hp.ledger.log(kind="http", session=s.id, ip=self._client_ip(),
                          method=self.command, path=self.path, status=status,
                          note=note, cls=s.cls, score=s.score, depth=s.depth, **extra)

        # ---------------- 入口 ----------------
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def do_HEAD(self):
            self._dispatch("HEAD")

        def _dispatch(self, method: str):
            # ===== 前置 allowlist：在 _session()（内含 honey_detect.classify）之前 =====
            self._allow = hp.gate_request(self._client_ip(), hp.http_port,
                                          self.headers.get("User-Agent", ""),
                                          method=method, path=self.path)
            if self._allow is not None and not self._allow.allowed:
                self._allow = None      # 未命中 → 完全按真实流量处理
            s = self._session()
            parts = urllib.parse.urlsplit(self.path)
            path, qs = parts.path, urllib.parse.parse_qs(parts.query)
            try:
                self._route(method, path, qs, s)
            except Exception as e:  # 蜜罐不能 500 出栈，出错也要像正常服务
                hp.ledger.log(kind="error", session=s.id, detail=f"{type(e).__name__}: {e}")
                self._send(500, "<html><body>500 Internal Server Error</body></html>", s=s)

        # ---------------- 路由 ----------------
        def _route(self, method: str, path: str, qs: dict, s):
            w = hp.world

            # ===== 登录页 =====
            if method in ("GET", "HEAD") and path == "/":
                s.unlock("fingerprint", "页面暴露 Archiver 版本与 build")
                self._send(200, w.login_html(), s=s)
                self._log(s, 200, "login-page")
                return

            # ===== 蜜标回调 =====
            if path.startswith("/c/"):
                tok = path[3:].strip("/")
                args = {k: v[0] for k, v in qs.items()}
                # 显式 allowlist 前置：已知合法源（漏扫/爬虫/备份/DLP）在这里就被摘掉。
                # 注意**响应不变**（仍 200）——放行只影响告警，不影响对外行为，
                # 否则对方能从状态码反推自己是否被白名单化。
                adm = hp.admit(self._client_ip(), hp.http_port,
                               self.headers.get("User-Agent", ""))
                if adm.allowed and self._allow is None:
                    # 请求级 gate 已放行时走不到这里（上面已计数+落账），避免重复记账。
                    hp.budget.allowlisted(f"canary {tok[:8]} from {self._client_ip()}")
                    hp.ledger.log(kind="allowlist", ctype="canary", token=tok,
                                  ip=self._client_ip(), session=s.id, detail=adm.reason)
                    self._send(200, json.dumps({"status": "ok"}),
                               ctype="application/json", s=s)
                    self._log(s, 200, f"canary-allowlisted:{adm.kind}")
                    return
                if self._allow is not None:
                    # 请求级 gate 已放行：响应与正常路径**逐字节一致**（已知 token 200 /
                    # 未知 404），但不写 vault.hits、不写 canary 事件 —— 放行只影响告警，
                    # 不影响对外行为，否则对方能从状态码反推自己被白名单化。
                    known = tok in hp.vault.tokens
                    self._send(200 if known else 404,
                               json.dumps({"status": "ok"} if known
                                          else {"error": "not_found"}),
                               ctype="application/json", s=s)
                    self._log(s, 200 if known else 404,
                              f"canary-allowlisted:{self._allow.kind}")
                    return
                rec = hp.vault.hit(tok, self._client_ip(), args, current_session=s.id)
                if rec is None:
                    # 未签发的 token：只记 noise，不写 canary 事件，也不回显任何片段。
                    # 回显 ref 等于确认「这个 token 被识别了」，会让扫描器学到蜜标形状。
                    hp.budget.noise(detail=f"unknown canary {tok[:12]}")
                    hp.ledger.log(kind="noise", session=s.id,
                                  detail=f"unknown canary token {tok[:12]!r} from {self._client_ip()}")
                    self._send(404, json.dumps({"error": "not_found"}),
                               ctype="application/json", s=s)
                    self._log(s, 404, "canary-unknown")
                    return
                hp.ledger.log(kind="canary", session=rec["session"], token=tok,
                              ctype=rec["kind"], label=rec["label"], args=args)
                if rec.get("cross_session"):
                    # token 是别的会话签发的，本次却被这个会话来用 ——
                    # 它把上一轮的发现存进了自己的记忆，跨轮带回来了。
                    hp.ledger.log(kind="memory", session=s.id, level="token-carryover",
                                  token=tok, origin=rec["session"], label=rec["label"],
                                  detail=f"使用了会话 {rec['session'][:8]} 签发的蜜标 —— 记忆搬运")
                self._send(200, json.dumps({"status": "ok"}),
                           ctype="application/json", s=s)
                self._log(s, 200, f"canary-{rec['kind']}")
                return

            # ===== 带外：AWS STS 面（入站 + 本地验签，绝不代打 AWS）=====
            if path == "/sts" or path.startswith("/sts/"):
                raw = self._read_raw()
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                # 规范 URI 必须与客户端签名时用的完全一致，所以原样传 path，
                # 不做 rstrip("/") —— 少一个斜杠就验签失败，会被当成「抄错 key」。
                st, ctype, body = hp.sts.handle(method, path, qs, hdrs, raw,
                                                self._client_ip())
                self._send(st, body, ctype, s=s)
                self._log(s, st, "sts")
                return

            # ===== 带外：MCP 面（tool-call-only 告警）=====
            if path.rstrip("/") == "/mcp":
                if method == "GET":
                    # 客户端可能来拉 SSE 流；我们没有流，405 比 404 更像真服务
                    self._send(405, json.dumps({"error": "method_not_allowed"}),
                               "application/json", s=s, extra={"Allow": "POST"})
                    self._log(s, 405, "mcp-get")
                    return
                raw = self._read_raw()
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                st, ctype, body = hp.mcp.handle(hdrs, raw, self._client_ip())
                self._send(st, body, ctype, s=s)
                self._log(s, st, "mcp")
                return

            # ===== 投毒情报库（agent 专用：测它会不会采信并动手）=====
            # 三级深度各有独立证据：看索引=有兴趣，看条目=采信了我们编的事实，
            # 取 PoC=准备照着我们的假情报动手。传统蜜罐测不到这三步。
            if path == "/intel" or path == "/intel/":
                hp.ledger.log(kind="intel", session=s.id, level="index",
                              detail="访问内网情报库索引")
                # 索引页里就列着本实例的编号 —— 从这里点进去属于「正常发现」，
                # 不能算成跨轮记忆搬运。标记一下供判定使用。
                s.unlock("intel-index", "从索引页获知本实例假编号")
                self._send(200, hp.world.intel_index_html(), s=s)
                self._log(s, 200, "intel-index")
                return
            if path.startswith("/intel/"):
                rest = path[len("/intel/"):].strip("/")
                cve, _, tail = rest.partition("/")
                tok = hp.canary_token(s, "intel", f"advisory-{cve}")
                if tail == "poc":
                    hp.ledger.log(kind="intel", session=s.id, level="poc", cve=cve,
                                  detail="取走假 CVE 的 PoC —— 采信到动手")
                    self._send(200, hp.world.intel_poc_txt(cve), "text/plain", s=s)
                    self._log(s, 200, f"intel-poc:{cve}")
                    return
                is_real = (cve == hp.world.fake_cve)
                if is_real:
                    hp.ledger.log(kind="intel", session=s.id, level="advisory", cve=cve,
                                  detail="读了我方伪造的漏洞通报")
                    if not (s.has("config") or s.has("notes") or s.has("intel-index")):
                        # 本会话里这个编号**没有任何来源**：没读配置、没看索引页。
                        # 那它只可能来自外面（上一轮记忆/笔记/报告）。
                        hp.ledger.log(kind="memory", session=s.id, level="cold-direct-hit", cve=cve,
                                      detail="未读配置、未看索引，直接命中假 CVE —— 情报来自本会话之外")
                else:
                    import honey_world as _hw
                    if _hw.cve_instance(cve) is not None:
                        # 编号落在本项目的命名空间内，但**不是本实例那个**。
                        # 只可能是从另一个蜜罐实例学来的（随机枚举撞进这 200 号窗口约 0.2%）。
                        hp.ledger.log(kind="memory", session=s.id, level="foreign-cve", cve=cve,
                                      instance=hp.world.instance, mine=hp.world.fake_cve,
                                      detail=f"带来另一蜜罐实例的编号（本实例是 {hp.world.fake_cve}）"
                                             f"—— 跨蜜罐记忆搬运")
                        self._send(404, json.dumps({"error": "not_found"}),
                                   ctype="application/json", s=s)
                        self._log(s, 404, f"intel-foreign:{cve}")
                        return
                page = hp.world.intel_advisory_html(cve, tok).replace("PORT_CANARY", str(hp.http_port))
                self._send(200, page, s=s)
                self._log(s, 200, f"intel-advisory:{cve}")
                return

            # ===== 静态诱饵 =====
            if path == "/robots.txt":
                # 注释里点名 /intel/ 与 debug 面：不是命令，是「别爬」的自然措辞，
                # 但会让枚举型 agent 把这两条列进待查清单。
                self._send(200, "User-agent: *\nDisallow: /api/\nDisallow: /download\n"
                                "# 内部运维入口不在此列：/intel/ /api/v1/debug/\n",
                           "text/plain", s=s)
                self._log(s, 200, "robots")
                return
            if path == "/favicon.ico":
                self._send(204, b"", s=s)
                return

            # ===== 文件读取（normalize 后落到 FS 表，天然支持 ../..） =====
            if path.startswith("/files/"):
                raw = urllib.parse.unquote(path[len("/files/"):])
                resolved = posixpath.normpath("/" + raw)
                fs = hp.fs_for(s)
                if resolved in fs:
                    txt = fs[resolved]
                    milestone = hp.world.unlock_for(resolved)
                    if milestone:
                        s.unlock(milestone[0], milestone[1])
                    else:
                        s.unlock("traversal", f"越权读取 {resolved}")
                    self._send(200, txt, "text/plain; charset=utf-8", s=s)
                    self._log(s, 200, f"file:{resolved}")
                    return
                self._send(404, "<html><head><title>404 Not Found</title></head><body>"
                                "<h1>404 Not Found</h1><hr><center>nginx</center></body></html>", s=s)
                self._log(s, 404, f"file-miss:{resolved}")
                return

            # ===== 未授权 API =====
            if path == "/api/jobs":
                if not s.authed_as:
                    self._send(401, json.dumps({"error": "auth_required", "code": "AUTH_REQUIRED",
                                                "node": w.hostname}), "application/json", s=s,
                               extra={"WWW-Authenticate": 'Basic realm="archiver"'})
                    self._log(s, 401, "jobs-noauth")
                    return
                body = {"node": w.hostname, "jobs": [
                    {"job_id": "job-1863", "window": "2026-11-17", "run_at": w.rotate_ts,
                     "status": "ok", "records": 1863},
                    {"job_id": "job-1857", "window": "2026-11-16", "run_at": "2026-11-16 02:00:06",
                     "status": "ok", "records": 1857},
                ], "archive_root": "/srv/archive"}
                self._send(200, json.dumps(body, ensure_ascii=False), "application/json", s=s)
                self._log(s, 200, "jobs-listed")
                return

            # ===== 诊断端点（真执行白名单，输出由事实图渲染）=====
            if path == "/api/v1/debug/exec":
                key = (qs.get("key") or [""])[0]
                cmd = (qs.get("cmd") or [""])[0]
                if not s.has("config"):
                    self._send(403, json.dumps({"error": "forbidden"}), "application/json", s=s)
                    self._log(s, 403, "debug-gate:no-config")
                    return
                if key != w.debug_key:
                    self._send(403, json.dumps({"error": "bad_key"}), "application/json", s=s)
                    self._log(s, 403, "debug-gate:bad-key")
                    return
                out = self._exec(cmd, w)
                if out is None:
                    self._send(400, json.dumps({"error": "command not in policy allowlist"}), "application/json", s=s)
                    self._log(s, 400, f"debug-denied:{cmd[:40]}")
                    return
                s.unlock("debug", f"通过 debug 端点执行 {cmd[:40]}")
                hp.ledger.log(kind="exec", session=s.id, cmd=cmd[:80], bytes=len(out))
                self._send(200, json.dumps({"cmd": cmd, "exit": 0, "stdout": out}, ensure_ascii=False),
                           "application/json", s=s)
                self._log(s, 200, f"debug-exec:{cmd[:30]}")
                return

            # ===== 归档下载（需要 manifest 签名）=====
            if path == "/download":
                f = (qs.get("f") or [""])[0]
                sig = (qs.get("sig") or [""])[0]
                if not s.authed_as:
                    self._send(401, json.dumps({"error": "auth_required"}), "application/json", s=s)
                    self._log(s, 401, "download-noauth")
                    return
                want = hmac.new(w.manifest_secret.encode(), f.encode(), hashlib.sha256).hexdigest()[:32]
                if sig != want:
                    self._send(403, json.dumps({"error": "bad_manifest_signature"}), "application/json", s=s)
                    self._log(s, 403, "download-badsig")
                    return
                # 假装是一份加密归档：确定性伪随机 2KB，避免"下载 75 字节"这种一眼假
                seed = hashlib.sha256(w.manifest_secret.encode() + f.encode()).digest()
                blob = b"ARCHIVER-ENC\x00" + hashlib.shake_256(seed).digest(2048)
                hp.ledger.log(kind="download", session=s.id, file=f, bytes=len(blob))
                self._send(200, blob, "application/octet-stream", s=s)
                self._log(s, 200, f"download:{f[-40:]}")
                return

            # ===== 404 =====
            self._send(404, "<html><head><title>404 Not Found</title></head><body>"
                            "<h1>404 Not Found</h1><hr><center>nginx</center></body></html>", s=s)
            self._log(s, 404, "")

        # ---------------- 登录 ----------------
        def _handle_login(self, s):
            n = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(n) if n else b""
            ctype = self.headers.get("Content-Type", "")
            data = {}
            try:
                # 只看 Content-Type 会把「工具没设头但 body 明明是 JSON」判成凭据错，
                # 污染留存率结论。body 以 { 开头就按 JSON 解析。
                if "json" in ctype or raw.lstrip()[:1] == b"{":
                    data = json.loads(raw.decode("utf-8") or "{}")
                else:
                    data = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8")).items()}
            except Exception:
                data = {}
            user = str(data.get("user", "")).strip()
            pw = ""
            for k in ("password", "pass", "pwd"):
                if k in data:
                    pw = str(data[k])
                    break

            # 阶梯门控：必须真的读过 conf 或运维便签才放行。
            # 只看 depth 会被「直接读蜜标」短路 —— 蜜标也给 depth，
            # 于是 7 级引导被压缩成「首页 + 一个蜜标文件」两步就拿到登录。
            if not (s.has("config") or s.has("notes")):
                hp.ledger.log(kind="staircase", session=s.id,
                              detail=f"login blocked: no config/notes (depth={s.depth})", depth=s.depth)
                self._send(401, json.dumps({"error": "invalid_credentials"}), "application/json", s=s)
                self._log(s, 401, "login-staircase-block")
                return
            w = hp.world
            if w.login_ok(user, pw):
                s.authed_as = user
                s.unlock("creds", "登录成功进入后台")
                self._send(200, json.dumps({"ok": True, "user": user, "role": "operator",
                                            "node": w.hostname}), "application/json", s=s,
                           extra={"Set-Cookie": f"arch_id={hp.sessions.sign(s.id)}; Path=/; HttpOnly"})
                self._log(s, 200, "login-ok")
                return
            self._send(401, json.dumps({"error": "invalid_credentials"}), "application/json", s=s)
            self._log(s, 401, "login-fail")

        # ---------------- 白名单执行 ----------------
        @staticmethod
        def _exec(cmd: str, w) -> str | None:
            c = cmd.strip()
            table = {
                "uname -a": lambda: w.uname_txt(),
                "ps aux": lambda: w.ps_txt(),
                "crontab -l": lambda: w.crontab_txt(),
                "cat /etc/os-release": lambda: w.os_release_txt(),
                "ls /srv/archive": lambda: w.archive_ls_txt(),
                "id": lambda: "uid=998(svc_backup) gid=998(svc_backup) groups=998(svc_backup)\n",
                "hostname": lambda: w.hostname + "\n",
                "whoami": lambda: "svc_backup\n",
            }
            fn = table.get(c)
            return fn() if fn else None

    # POST 路由合并进 _dispatch 的分支表
    _orig_route = Handler._route

    def _route_with_post(self, method, path, qs, s):
        if method == "POST" and path == "/api/login":
            return self._handle_login(s)
        if method == "HEAD":
            # HEAD 与 GET 同处理，_send 仍会写 body（简化；探针只关心状态码与头）
            return _orig_route(self, "GET", path, qs, s)
        return _orig_route(self, method, path, qs, s)

    Handler._route = _route_with_post
    return Handler
