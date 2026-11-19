"""honey_oob.py — 带外 token：归因不再依赖攻击者连回我们的 HTTP 面

浮世原有三类蜜标（bait URL / 假 AWS 凭据 / 身份回调）都要求攻击者访问我们的
HTTP 服务。蜜罐被识破、被隔离、只跑 token 模式时，这条链就断了。本模块把触发点
挪进攻击者**自己的工具链**：

  dns  —— 攻击者解析域名即命中。解析发生在它的 shell / 扫描器 / 后门里，不需要
          连我们任何端口。本地只读监听：不递归、不转发、无 upstream。
  aws  —— 一把**静态不可识别**的 IAM key。外观与真 key 同构（AKIA + 16 位 base32，
          40 位 base64 secret），只有有人拿它签一次 SigV4 打到我们的 STS 面才命中。
          验签在本地用我们存的 secret 算，**绝不代打 AWS**。
  mcp  —— 埋在 mcp.json 里的 Bearer token。只有 JSON-RPC `tools/call` 才算告警；
          读配置、`initialize`、`tools/list` 都只是「摸到了」，不算「用了」——
          这就是 tool-call-only 告警的含义。

红线（浮世是 Rule of Two 合规实例：无真出站、无真 shell）：
  · DNS sink 只回 NXDOMAIN（或可选 sinkhole A 记录），且只回给刚发来查询的那个
    源地址。没有 resolver、没有 forwarder、没有上游。
  · STS sink 是**入站** HTTP 处理器。签名校验用 stdlib hmac/hashlib 本地算。
  · `NoEgressGuard` 把「不出站」变成可执行断言：patch socket.connect /
    create_connection / getaddrinfo / sendto，任何非回环目标都记账并抛错。
    自测要求「出站尝试 == 0」，让红线是测试而不是注释。

为什么 AWS key 要「不可检测」：现有工件里的 key 是占位形状（含 `...`），免费威胁
情报和任何一条静态规则都能认出它是假的，攻击者根本不会拿去用——token 一条都不
会响。可用的 token 必须**结构正确 + 无标记 + 每会话唯一**，靠「被使用」而不是靠
「长得像」来触发。
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import secrets
import socket
import string
import struct
import sys
import threading
import time
from urllib.parse import parse_qsl, quote

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
KIND_DNS = "dns"
KIND_AWS = "aws"
KIND_MCP = "mcp"
OOB_KINDS = (KIND_DNS, KIND_AWS, KIND_MCP)

SEV_ALERT = "alert"          # 硬命中：进账本，进噪声预算的分子
SEV_TOUCH = "touch"          # 摸到了但没「用」：只记，不算告警
SEV_ALLOWED = "allowlisted"  # 被显式放行的源：连噪声都不算
SIGV4_ALGO = "AWS4-HMAC-SHA256"

_AWS_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"   # base32，与真实 AKID 一致
_B32_LOWER = "abcdefghijklmnopqrstuvwxyz234567"
_SECRET_ALPHABET = string.ascii_letters + string.digits + "/+"
_MCP_ALPHABET = string.ascii_letters + string.digits + "-_"

# 静态识别会命中这些词。真实 IAM key 由 AWS 随机生成，不含任何语义串；
# token 一旦带语义，任何一条 grep 规则就能把它挑出来，等于没埋。
STATIC_MARKERS = (
    "CANARY", "HONEY", "TRAP", "TEST", "FAKE", "DEMO", "SAMPLE", "DUMMY",
    "EXAMPLE", "PLACEHOLDER", "XXXX", "CHANGEME", "TODO",
)
# AWS 官方文档里的示例 key —— 威胁情报库里最常见的「假 key」指纹
AWS_DOC_EXAMPLE_AKID = "AKIAIOSFODNN7EXAMPLE"

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 99: "SPF",
               255: "ANY", 257: "CAA"}


# ---------------------------------------------------------------------------
# 静态不可检测性：把「不可检测」写成可执行检查，而不是一句形容词
# ---------------------------------------------------------------------------
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in
                (s.count(ch) for ch in set(s)))


def _has_run(s: str, width: int = 4) -> bool:
    """连续 width 个相同字符：随机 key 里几乎不可能出现。"""
    return any(len(set(s[i:i + width])) == 1 for i in range(len(s) - width + 1))


def _has_sequence(s: str, width: int = 4) -> bool:
    """字母/数字顺序递进（ABCD、4321）：人手编 key 的典型痕迹。"""
    for i in range(len(s) - width + 1):
        seg = s[i:i + width]
        vals = [ord(c) for c in seg]
        if all(vals[j] + 1 == vals[j + 1] for j in range(width - 1)):
            return True
        if all(vals[j] - 1 == vals[j + 1] for j in range(width - 1)):
            return True
    return False


def static_detectability(akid: str, secret: str, extra_words: tuple[str, ...] = ()) -> list[str]:
    """返回静态识别器会抓住的特征列表。空列表 = 过。

    这不是「看起来像」，是可复算的判据：长度/字符集/语义串/熵/重复/序列/
    与官方示例 key 撞车/与实例特征串撞车。
    """
    bad: list[str] = []
    if len(akid) != 20 or not akid.startswith("AKIA"):
        bad.append(f"AKID 形状不对（len={len(akid)}, prefix={akid[:4]!r}）")
    body = akid[4:]
    if set(body) - set(_AWS_KEY_ALPHABET):
        bad.append(f"AKID 含非 base32 字符：{sorted(set(body) - set(_AWS_KEY_ALPHABET))}")
    if len(secret) != 40:
        bad.append(f"secret 长度 {len(secret)} ≠ 40")
    if set(secret) - set(_SECRET_ALPHABET):
        bad.append("secret 含非法字符")
    joined = (akid + secret).upper()
    hits = [m for m in STATIC_MARKERS if m in joined]
    if hits:
        bad.append(f"命中语义标记 {hits}")
    if akid.upper() == AWS_DOC_EXAMPLE_AKID:
        bad.append("与 AWS 文档示例 key 相同（所有情报库都收录了它）")
    for w in extra_words:
        if w and len(w) >= 4 and w.upper() in joined:
            bad.append(f"含实例特征串 {w!r}：可跨实例关联")
    if _has_run(akid + secret):
        bad.append("存在 4 连重复字符")
    if _has_sequence(secret):
        bad.append("存在 4 连递增/递减序列")
    if _entropy(body) < 3.8:
        bad.append(f"AKID 主体熵过低 {_entropy(body):.2f}")
    if _entropy(secret) < 4.0:
        bad.append(f"secret 熵过低 {_entropy(secret):.2f}")
    return bad


def _rand(n: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def gen_aws_key() -> tuple[str, str]:
    """生成一把通过全部静态检查的 IAM key。重试而不是「尽力」——
    token 一旦可被静态识别，这条归因链就是废的。"""
    for _ in range(200):
        akid = "AKIA" + _rand(16, _AWS_KEY_ALPHABET)
        secret = _rand(40, _SECRET_ALPHABET)
        if not static_detectability(akid, secret):
            return akid, secret
    raise RuntimeError("无法生成通过静态检查的 key（熵源异常？）")


# ---------------------------------------------------------------------------
# SigV4 本地校验（stdlib，不连 AWS）
# ---------------------------------------------------------------------------
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _quote(s: str, safe: str = "-_.~") -> str:
    return quote(s, safe=safe)


def _canonical_uri(path: str) -> str:
    if not path:
        return "/"
    segs = path.split("/")
    return "/".join(_quote(s) for s in segs) or "/"


def _canonical_query(query: dict[str, list[str]] | list[tuple[str, str]]) -> str:
    items = query.items() if isinstance(query, dict) else query
    pairs: list[tuple[str, str]] = []
    for k, v in items:
        vs = v if isinstance(v, (list, tuple)) else [v]
        for one in vs:
            if k == "X-Amz-Signature":
                continue
            pairs.append((_quote(str(k)), _quote(str(one))))
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def parse_credential(headers: dict[str, str], query) -> dict:
    """从请求里抽取 SigV4 凭据范围。**不验签、不发包。**

    返回 {akid, date, region, service, signed_headers, signature, amz_date, error}。
    单独出来是因为 STS 面要「先认 key 再验签」：只有认出来是我们签发的 key，
    才值得用它的 secret 去算一次 HMAC。否则任何陌生请求都能让我们做一次
    无用的 600 次哈希运算 —— 那就是一个免费的打点放大面。
    """
    out = {"akid": "", "date": "", "region": "", "service": "",
           "signed_headers": "", "signature": "", "amz_date": "",
           "error": ""}
    auth = headers.get("authorization", "") or ""
    out["amz_date"] = headers.get("x-amz-date", "") or ""
    cred = ""
    if auth.startswith(SIGV4_ALGO + " "):
        parts = {}
        for kv in auth[len(SIGV4_ALGO) + 1:].split(","):
            k, _, v = kv.strip().partition("=")
            parts[k] = v
        cred = parts.get("Credential", "")
        out["signed_headers"] = parts.get("SignedHeaders", "")
        out["signature"] = parts.get("Signature", "")
    elif query:
        q = dict(query.items()) if isinstance(query, dict) else dict(query)

        def one(name: str) -> str:
            v = q.get(name)
            return (v[0] if isinstance(v, (list, tuple)) and v else v) or ""

        cred = one("X-Amz-Credential")
        out["signature"] = one("X-Amz-Signature")
        out["signed_headers"] = one("X-Amz-SignedHeaders")
        out["amz_date"] = one("X-Amz-Date") or out["amz_date"]

    if not cred:
        out["error"] = "no-sigv4-credential"
        return out
    try:
        akid, date, region, service, term = cred.split("/")
    except ValueError:
        out["error"] = "malformed-credential-scope"
        return out
    out.update(akid=akid, date=date, region=region, service=service)
    if term != "aws4_request":
        out["error"] = f"bad-terminal {term!r}"
    return out


def verify_sigv4(*, method: str, path: str, query, headers: dict[str, str],
                 body: bytes, secret: str) -> dict:
    """用我们自己的 secret 复算签名。**不发任何网络请求。**

    返回 {valid, akid, region, service, signed_headers, amz_date, error}。
    valid=True 的语义很硬：对方不仅拿到了 key，还跑了一个真实的 SigV4 签名器
    （AWS CLI / SDK / boto3）——不是 grep 出来的字符串，是**在用**。
    """
    p = parse_credential(headers, query)
    out = {"valid": False, "akid": p["akid"], "region": p["region"],
           "service": p["service"], "signed_headers": p["signed_headers"],
           "amz_date": p["amz_date"], "error": p["error"]}
    if p["error"]:
        return out
    if not p["signature"]:
        out["error"] = "no-signature"
        return out
    if not p["amz_date"]:
        out["error"] = "missing-x-amz-date"
        return out
    if not p["signed_headers"]:
        out["error"] = "missing-signed-headers"
        return out

    names = [h.strip().lower() for h in p["signed_headers"].split(";") if h.strip()]
    canon_headers = []
    for n in names:
        v = headers.get(n)
        if v is None:
            out["error"] = f"signed-header-absent:{n}"
            return out
        canon_headers.append(f"{n}:{' '.join(str(v).split())}\n")
    payload_hash = headers.get("x-amz-content-sha256") or hashlib.sha256(body).hexdigest()
    canonical_request = "\n".join([
        method.upper(),
        _canonical_uri(path),
        _canonical_query(query or {}),
        "".join(canon_headers),
        ";".join(names),
        payload_hash,
    ])
    scope = f"{p['date']}/{p['region']}/{p['service']}/aws4_request"
    sts = "\n".join([SIGV4_ALGO, p["amz_date"], scope,
                     hashlib.sha256(canonical_request.encode()).hexdigest()])
    k = _hmac(("AWS4" + secret).encode(), p["date"])
    k = _hmac(k, p["region"])
    k = _hmac(k, p["service"])
    k = _hmac(k, "aws4_request")
    expect = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    out["valid"] = hmac.compare_digest(expect, p["signature"].lower())
    if not out["valid"]:
        out["error"] = "signature-mismatch"
    return out


# ---------------------------------------------------------------------------
# 不出站守卫：把红线做成可执行断言
# ---------------------------------------------------------------------------
class EgressBlocked(RuntimeError):
    """被 NoEgressGuard 拦下的出站尝试（不是普通错误：这是红线告警）。"""


class NoEgressGuard:
    """拦截并记录一切主动出站。只放行回环目标。

    sendto 单独处理：DNS sink 必须回包给对方，但**只回给刚发来查询的那个地址**。
    这里用调用方身份（honey_oob:DnsSink._reply）而不是地址白名单来判定——
    地址白名单会把「回给攻击者」变成合法出站，那是自欺。
    """

    ALLOWED_SENDERS = ("honey_oob:DnsSink._loop",)

    def __init__(self):
        self.attempts: list[dict] = []
        self._saved: list[tuple] = []
        self._local = threading.local()

    # -- 判定 --
    @staticmethod
    def _is_loopback(host: str) -> bool:
        try:
            a = ipaddress.ip_address(str(host).strip("[]"))
        except ValueError:
            return str(host) in ("localhost", "")
        if a.version == 6 and a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        return a.is_loopback or a.is_unspecified

    def _caller(self) -> str:
        f = sys._getframe(2)
        while f is not None:
            fn = f.f_code.co_filename
            if fn.endswith("honey_oob.py"):
                return f"honey_oob:{f.f_code.co_name}"
            f = f.f_back
        return "?"

    def _note(self, what: str, target) -> None:
        self.attempts.append({"what": what, "target": str(target)[:200],
                              "caller": self._caller(), "ts": time.time()})

    # -- patch --
    def __enter__(self) -> "NoEgressGuard":
        self._install()
        return self

    def __exit__(self, *exc) -> None:
        self._restore()

    def _install(self) -> None:
        guard = self
        orig_connect = socket.socket.connect
        orig_connect_ex = socket.socket.connect_ex
        orig_sendto = socket.socket.sendto
        orig_create = socket.create_connection
        orig_gai = socket.getaddrinfo

        def connect(self, address, *a, **kw):
            if guard._is_loopback(address[0] if isinstance(address, tuple) else address):
                return orig_connect(self, address, *a, **kw)
            guard._note("connect", address)
            raise EgressBlocked(f"出站被拦：connect {address}")

        def connect_ex(self, address, *a, **kw):
            if guard._is_loopback(address[0] if isinstance(address, tuple) else address):
                return orig_connect_ex(self, address, *a, **kw)
            guard._note("connect_ex", address)
            return 111  # ECONNREFUSED，不抛错让调用方以为「目标关着」

        def sendto(self, data, *a, **kw):
            if guard._caller() in guard.ALLOWED_SENDERS:
                return orig_sendto(self, data, *a, **kw)
            dest = a[-1] if a else kw.get("address")
            host = dest[0] if isinstance(dest, tuple) else dest
            if host is not None and guard._is_loopback(host):
                return orig_sendto(self, data, *a, **kw)
            guard._note("sendto", dest)
            raise EgressBlocked(f"出站被拦：sendto {dest}")

        def create_connection(address, *a, **kw):
            if guard._is_loopback(address[0]):
                return orig_create(address, *a, **kw)
            guard._note("create_connection", address)
            raise EgressBlocked(f"出站被拦：create_connection {address}")

        def getaddrinfo(host, port, *a, **kw):
            if guard._is_loopback(host):
                return orig_gai(host, port, *a, **kw)
            guard._note("getaddrinfo", f"{host}:{port}")
            raise EgressBlocked(f"出站被拦：解析外部主机名 {host!r}")

        self._saved = [
            (socket.socket, "connect", orig_connect),
            (socket.socket, "connect_ex", orig_connect_ex),
            (socket.socket, "sendto", orig_sendto),
            (socket, "create_connection", orig_create),
            (socket, "getaddrinfo", orig_gai),
        ]
        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        socket.socket.sendto = sendto
        socket.create_connection = create_connection
        socket.getaddrinfo = getaddrinfo

    def _restore(self) -> None:
        for obj, name, orig in self._saved:
            setattr(obj, name, orig)
        self._saved = []

    @property
    def clean(self) -> bool:
        return not self.attempts


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------
class OutOfBandVault:
    """三类带外 token 的签发 / 解析 / 命中记账。

    没有 allowlist 时所有命中都算；给了 allowlist 就在**最内层**先过滤——
    放行的源连 noise 都不进，避免「自己的漏扫把噪声预算打满」这类经典事故。
    """

    def __init__(self, public_host: str = "127.0.0.1", http_port: int = 0,
                 zone: str = "", account: str = "", hit_hook=None,
                 allowlist=None, dedupe_window_s: float = 60.0):
        self.public_host = public_host
        self.http_port = http_port
        self.zone = (zone or f"{public_host}").strip(".")
        self.account = account or f"{secrets.randbelow(9) + 1}" + "".join(
            str(secrets.randbelow(10)) for _ in range(11))
        self.hit_hook = hit_hook
        self.allowlist = allowlist
        self.dedupe_window_s = dedupe_window_s
        self.tokens: dict[str, dict] = {}       # token/akid -> meta
        self.events: list[dict] = []            # 全部事件（含 touch / allowlisted）
        self._last_alert: dict[str, float] = {}
        self.counts = {"alert": 0, "touch": 0, "allowlisted": 0,
                       "dup_suppressed": 0, "unissued": 0}

    # ---------------- 签发 ----------------
    def _put(self, token: str, kind: str, session: str, label: str, meta: dict) -> dict:
        rec = {"token": token, "kind": kind, "session": session, "label": label,
               "issued": time.time(), **meta}
        self.tokens[token] = rec
        return rec

    def issue_dns(self, session: str, label: str) -> str:
        tok = _rand(20, _B32_LOWER)
        self._put(tok, KIND_DNS, session, label, {"fqdn": f"{tok}.{self.zone}"})
        return tok

    def issue_aws(self, session: str, label: str) -> dict:
        akid, secret = gen_aws_key()
        self._put(akid, KIND_AWS, session, label, {"secret": secret})
        return {"access_key_id": akid, "secret_access_key": secret}

    def issue_mcp(self, session: str, label: str) -> str:
        tok = "mcp_" + _rand(40, _MCP_ALPHABET)
        self._put(tok, KIND_MCP, session, label, {})
        return tok

    def resolve(self, token: str) -> dict | None:
        return self.tokens.get(token)

    @staticmethod
    def _material(kind: str, evidence: dict):
        """去重只看「实质相同」的重试。

        不能只按 token+来源去重：一次验签通过的 GetCallerIdentity 和一次验签
        失败的请求是两件不同的事实（前者证明对方在真签名，后者可能是抄错了），
        合并会吞掉更有价值的那条。MCP 按 tool 名区分，DNS 按 qtype 区分。
        """
        if kind == KIND_AWS:
            return ("aws", evidence.get("signature_valid"), evidence.get("action"))
        if kind == KIND_MCP:
            return ("mcp", evidence.get("tool"))
        if kind == KIND_DNS:
            return ("dns", evidence.get("qtype"), evidence.get("payload_labels"))
        return (kind,)

    def _emit(self, rec: dict) -> dict:
        """落账本。异常必须吞掉：蜜罐的账本不能反过来打挂蜜罐，
        但**吞异常不等于不记录**——调用点保证 rec 已进 self.events。"""
        if self.hit_hook:
            try:
                self.hit_hook(rec)
            except Exception:          # noqa: BLE001
                pass
        return rec

    # ---------------- 命中 ----------------
    def record(self, kind: str, token: str, remote: str, severity: str,
               evidence: dict | None = None) -> dict | None:
        meta = self.tokens.get(token)
        if meta is None:
            self.counts["unissued"] += 1
            return None
        if severity != SEV_TOUCH and self.allowlist is not None:
            d = self.allowlist.check(remote)
            if d.allowed:
                rec = {"ts": time.time(), "kind": kind, "token": token, "remote": remote,
                       "severity": SEV_ALLOWED, "session": meta["session"],
                       "label": meta["label"], "allow_kind": d.kind,
                       "detail": d.reason, "evidence": evidence or {}}
                self.events.append(rec)
                self.counts[SEV_ALLOWED] += 1
                return self._emit(rec)
        key = f"{kind}:{token}:{remote}:{self._material(kind, evidence or {})!r}"[:220]
        now = time.time()
        dup = severity == SEV_ALERT and (now - self._last_alert.get(key, 0)) < self.dedupe_window_s
        if severity == SEV_ALERT:
            self._last_alert[key] = now
            if dup:
                self.counts["dup_suppressed"] += 1
        rec = {"ts": now, "kind": kind, "token": token, "remote": remote,
               "severity": severity, "session": meta["session"], "label": meta["label"],
               "evidence": evidence or {}, "dup": dup}
        self.events.append(rec)
        self.counts[severity] = self.counts.get(severity, 0) + 1
        return self._emit(rec)

    # ---------------- 统计 ----------------
    def alerts(self) -> list[dict]:
        return [e for e in self.events if e["severity"] == SEV_ALERT and not e.get("dup")]

    def by_kind(self) -> dict[str, int]:
        out = {k: 0 for k in OOB_KINDS}
        for e in self.alerts():
            out[e["kind"]] = out.get(e["kind"], 0) + 1
        return out

    def summary(self) -> dict:
        return {"kinds": self.by_kind(), "counts": dict(self.counts),
                "tokens_issued": len(self.tokens),
                "sessions": len({m["session"] for m in self.tokens.values()})}

    # ---------------- 工件 ----------------
    def aws_credentials_text(self, session: str) -> tuple[str, str]:
        k = self.issue_aws(session, "aws-credentials")
        txt = ("[default]\n"
               f"aws_access_key_id = {k['access_key_id']}\n"
               f"aws_secret_access_key = {k['secret_access_key']}\n")
        return txt, k["access_key_id"]

    def aws_config_text(self, legacy: str = "") -> str:
        """在世界的 config 后面追加一个走内网 STS 的 profile。

        为什么**不**覆盖原 config：原件里的 `endpoint_url=.../c/<token>` 是
        身份外带（h/u/d 参数）唯一的上报口，demo 的 EXFIL-PROVEN 判定依赖它。
        覆盖掉它等于用新能力换掉旧证据链 —— 这不是升级，是拆东墙。

        所以两条链路并存，都上账：
          · `[default]`       —— 旧同步钩子，回调 /c/<token>（一碰就响）
          · `[profile archive-sync]` —— 新工具走内网 STS 代理，命中 /sts
        攻击者 `aws configure list-profiles` 一眼看到两个，两条都会试。
        """
        port = f":{self.http_port}" if self.http_port else ""
        block = (
            "\n[profile archive-sync]\n"
            "region = cn-north-1\n"
            "output = json\n"
            "# air-gapped 同步走内网 STS 代理\n"
            f"endpoint_url = http://{self.public_host}{port}/sts\n"
            "sts_regional_endpoints = regional\n")
        return (legacy.rstrip("\n") + "\n" + block) if legacy else block.lstrip("\n")

    def mcp_json_text(self, session: str) -> tuple[str, str]:
        tok = self.issue_mcp(session, "mcp-config")
        port = f":{self.http_port}" if self.http_port else ""
        obj = {
            "mcpServers": {
                "archiver-ops": {
                    "type": "http",
                    "url": f"http://{self.public_host}{port}/mcp",
                    "headers": {"Authorization": f"Bearer {tok}"},
                    "description": "归档节点运维工具（只读），生产变更请走审批",
                }
            }
        }
        return json.dumps(obj, ensure_ascii=False, indent=2) + "\n", tok

    def dns_hint(self, session: str) -> str:
        tok = self.issue_dns(session, "dns-hint")
        return f"<{tok}.{self.zone}>"


# ---------------------------------------------------------------------------
# DNS sink
# ---------------------------------------------------------------------------
class DnsSink:
    """只读 DNS 监听。

    三种请求只做一件事：识别 token、记账、回 NXDOMAIN（或可选 sinkhole）。
    没有递归、没有 forwarder、没有上游 —— 它不是一个 resolver，是一个记录器。

    反放大：NXDOMAIN 响应长度 == 查询长度（12 字节头 + 原样 question），
    天然 1:1，不会被拿去做反射攻击。sinkhole 模式只对**已签发 token** 回 A 记录，
    外人对任意名字都拿不到答案。
    """

    def __init__(self, vault: OutOfBandVault, bind: str = "127.0.0.1", port: int = 0,
                 answer_ip: str | None = None):
        self.vault = vault
        self.bind = bind
        self._want_port = port
        self.port = port
        self.answer_ip = answer_ip
        self.sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.queries = 0
        self.dropped = 0

    # ---------- 报文 ----------
    @staticmethod
    def parse_question(data: bytes):
        """返回 (labels, qtype, qclass, question_end) 或 None。

        查询里出现压缩指针 = 非法/攻击性报文，直接丢；QDCOUNT != 1 也丢，
        因为多问题查询是放大攻击的常用形状。
        """
        if len(data) < 12 or len(data) > 512:
            return None
        qd = struct.unpack("!H", data[4:6])[0]
        if qd != 1:
            return None
        i, labels = 12, []
        while True:
            if i >= len(data):
                return None
            ln = data[i]
            i += 1
            if ln == 0:
                break
            if ln & 0xC0:
                return None
            if ln > 63 or i + ln > len(data):
                return None
            labels.append(data[i:i + ln].decode("ascii", "replace"))
            i += ln
            if len(labels) > 16:
                return None
        if i + 4 > len(data):
            return None
        qtype, qclass = struct.unpack("!HH", data[i:i + 4])
        return labels, qtype, qclass, i + 4

    def _reply(self, data: bytes, end: int, rcode: int, answer: bytes = b"") -> bytes:
        # 只回给刚发来查询的源地址 —— 见 NoEgressGuard.ALLOWED_SENDERS
        ident = data[:2]
        qflags = struct.unpack("!H", data[2:4])[0]
        rd = qflags & 0x0100
        flags = 0x8000 | 0x0400 | rd | (rcode & 0xF)      # QR | AA | RD | RCODE, RA=0
        ancount = 1 if answer else 0
        hdr = ident + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
        return hdr + data[12:end] + answer

    def handle_packet(self, data: bytes, addr) -> bytes | None:
        self.queries += 1
        parsed = self.parse_question(data)
        if parsed is None:
            self.dropped += 1
            return None
        labels, qtype, _qclass, end = parsed
        qname = ".".join(labels).lower()
        tok = ""
        tok_idx = -1
        for i, lab in enumerate(labels):
            if self.vault.resolve(lab):
                tok, tok_idx = lab, i
                break
        if tok:
            payload = ".".join(labels[:tok_idx] + labels[tok_idx + 1:])
            self.vault.record(KIND_DNS, tok, addr[0], SEV_ALERT, {
                "qname": qname, "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
                "qtype_num": qtype, "qclass": _qclass,
                "payload_labels": payload[:200], "transport": "udp",
                "source_port": addr[1],
            })
            if self.answer_ip and qtype in (1, 255):     # 只对 A/ANY 回地址
                try:
                    ip = ipaddress.ip_address(self.answer_ip)
                except ValueError:
                    ip = None
                if ip is not None and ip.version == 4:
                    # 压缩指针 0xC00C 指回 question 里的名字，省一次重编码
                    answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip.packed)
                    return self._reply(data, end, 0, answer)
        else:
            self.vault.counts["unissued"] += 1
        return self._reply(data, end, 3)     # NXDOMAIN

    # ---------- 生命周期 ----------
    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, self._want_port))
        s.settimeout(0.25)
        self.sock = s
        self.port = s.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        assert self.sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                resp = self.handle_packet(data, addr)
                if resp:
                    self.sock.sendto(resp, addr)
            except Exception:      # 单包异常不能打死监听
                self.dropped += 1

    def stop(self) -> None:
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# AWS STS sink
# ---------------------------------------------------------------------------
class StsSink:
    """入站 STS 面。本地验签，绝不代打 AWS。

    为什么只认 GetCallerIdentity：它是攻击者拿到一把「可能有用」的 key 之后
    第一件做的事（`aws sts get-caller-identity` = 验证 key 有效性 + 拿账号 ID）。
    这个动作没有副作用，所以真人/agent 都会做；而它恰好只需要一次 SigV4 签名，
    签名里带着 key —— 我们不用出站就能确认「有人在用这把钥匙」。
    """

    def __init__(self, vault: OutOfBandVault):
        self.vault = vault

    def handle(self, method: str, path: str, query, headers: dict[str, str],
               body: bytes, remote: str) -> tuple[int, str, str]:
        form = {}
        if body and b"=" in body[:2000]:
            try:
                form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
            except Exception:
                form = {}
        target = headers.get("x-amz-target", "")
        action = (form.get("Action")
                  or target.rsplit(".", 1)[-1]
                  or (query.get("Action", [""])[0] if isinstance(query, dict)
                      and query.get("Action") else "")
                  or "")

        # 先认 key（纯解析），认出来才值得算 HMAC —— 陌生请求不该换我们一次签名运算
        cred = parse_credential(headers, query)
        akid = cred["akid"] or form.get("AWSAccessKeyId", "")

        meta = self.vault.resolve(akid) if akid else None
        if meta is None or meta["kind"] != KIND_AWS:
            self.vault.counts["unissued"] += 1
            return (403, "text/xml", self._error("InvalidClientTokenId",
                                                 "The security token included in the request is invalid."))
        # 有了 secret 才能真的验签
        ver = verify_sigv4(method=method, path=path, query=query, headers=headers,
                           body=body, secret=meta["secret"])
        self.vault.record(KIND_AWS, akid, remote, SEV_ALERT, {
            "action": action or "unknown",
            "signature_valid": ver["valid"],
            "sigv4": bool(ver["akid"]),
            "sdk": ver["valid"],       # 验签通过 = 对方在用真实签名器（CLI/SDK）
            "region": ver["region"], "service": ver["service"],
            "signed_headers": ver["signed_headers"], "amz_date": ver["amz_date"],
            "ua": headers.get("user-agent", "")[:160],
            "error": ver["error"],
        })
        if action == "GetCallerIdentity" or not action:
            return (200, "text/xml", self._get_caller_identity(meta))
        return (403, "text/xml", self._error(
            "AccessDenied", f"User is not authorized to perform: sts:{action}"))

    def _get_caller_identity(self, meta: dict) -> str:
        rid = secrets.token_hex(8).upper()
        acct = self.vault.account
        arn = f"arn:aws-cn:iam::{acct}:user/svc-archive-sync"
        uid = "AIDA" + _rand(16, _AWS_KEY_ALPHABET)
        return (
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n'
            "  <GetCallerIdentityResult>\n"
            f"    <Arn>{arn}</Arn>\n"
            f"    <UserId>{uid}</UserId>\n"
            f"    <Account>{acct}</Account>\n"
            "  </GetCallerIdentityResult>\n"
            f"  <ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>\n"
            "</GetCallerIdentityResponse>\n")

    @staticmethod
    def _error(code: str, msg: str) -> str:
        return ('<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">\n'
                f"  <Error><Type>Sender</Type><Code>{code}</Code><Message>{msg}</Message></Error>\n"
                f"  <RequestId>{secrets.token_hex(8).upper()}</RequestId>\n"
                "</ErrorResponse>\n")


# ---------------------------------------------------------------------------
# MCP sink
# ---------------------------------------------------------------------------
class McpSink:
    """MCP over HTTP 面。tool-call-only 告警。

    分级（这就是 tool-call-only 的可执行定义）：
      initialize / tools/list / resources/list / ping  → SEV_TOUCH（摸到了）
      tools/call                                        → SEV_ALERT（用了）
    读 mcp.json 本身不算任何事件——文件在 /files/ 面上，读它只是「看到了配置」。
    """

    PROTOCOL = "2025-06-18"
    TOOLS = [
        {"name": "archive.search", "description": "按窗口/主机检索归档索引（只读）",
         "inputSchema": {"type": "object",
                         "properties": {"query": {"type": "string"},
                                        "limit": {"type": "integer", "default": 20}},
                         "required": ["query"]}},
        {"name": "archive.fetch", "description": "拉取指定 job 的归档清单",
         "inputSchema": {"type": "object",
                         "properties": {"job_id": {"type": "string"}},
                         "required": ["job_id"]}},
        {"name": "archive.health", "description": "节点健康与队列状态",
         "inputSchema": {"type": "object", "properties": {}}},
    ]

    def __init__(self, vault: OutOfBandVault):
        self.vault = vault
        self.harness: list[dict] = []

    @staticmethod
    def _token(headers: dict[str, str], obj: dict, raw: bytes) -> str:
        auth = headers.get("authorization", "") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        if headers.get("x-mcp-token"):
            return headers["x-mcp-token"].strip()
        try:
            p = (obj.get("params") or {}).get("_meta") or {}
            if isinstance(p, dict) and p.get("token"):
                return str(p["token"])
        except AttributeError:
            pass
        if b"mcp_" in raw[:4096]:
            i = raw.find(b"mcp_")
            j = i
            while j < len(raw):
                c = raw[j:j + 1]
                if not (c.isalnum() or c in (b"-", b"_")):
                    break
                j += 1
            return raw[i:j].decode("ascii", "replace")
        return ""

    def handle(self, headers: dict[str, str], body: bytes, remote: str
               ) -> tuple[int, str, str]:
        try:
            obj = json.loads(body.decode("utf-8", "replace") or "{}")
        except Exception:
            return (400, "application/json", json.dumps(
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "Parse error"}}))
        if not isinstance(obj, dict):
            obj = {}
        tok = self._token(headers, obj, body)
        meta = self.vault.resolve(tok) if tok else None
        if meta is None or meta["kind"] != KIND_MCP:
            if not tok:
                self.vault.counts["unissued"] += 1
                return (401, "application/json",
                        json.dumps({"error": "unauthorized",
                                    "error_description": "missing bearer token"}))
            self.vault.counts["unissued"] += 1
            return (401, "application/json",
                    json.dumps({"error": "invalid_token"}))

        method = str(obj.get("method") or "")
        params = obj.get("params") or {}
        rid = obj.get("id")

        if method == "initialize":
            ci = (params.get("clientInfo") or {}) if isinstance(params, dict) else {}
            self.harness.append({"name": str(ci.get("name", ""))[:60],
                                 "version": str(ci.get("version", ""))[:40],
                                 "ts": time.time(), "remote": remote})
            self.vault.record(KIND_MCP, tok, remote, SEV_TOUCH,
                              {"rpc": method, "harness": ci.get("name", ""),
                               "client_version": ci.get("version", "")})
            return (200, "application/json", json.dumps({
                "jsonrpc": "2.0", "id": rid,
                "result": {"protocolVersion": self.PROTOCOL,
                           "capabilities": {"tools": {"listChanged": False}},
                           "serverInfo": {"name": "archiver-mcp", "version": "0.9.3"}}}))
        if method == "notifications/initialized":
            return (202, "application/json", "")
        if method == "tools/list":
            self.vault.record(KIND_MCP, tok, remote, SEV_TOUCH, {"rpc": method})
            return (200, "application/json", json.dumps({
                "jsonrpc": "2.0", "id": rid, "result": {"tools": self.TOOLS}}))
        if method in ("ping", "resources/list", "prompts/list"):
            self.vault.record(KIND_MCP, tok, remote, SEV_TOUCH, {"rpc": method})
            return (200, "application/json", json.dumps({
                "jsonrpc": "2.0", "id": rid, "result": {}}))
        if method == "tools/call":
            name = str((params or {}).get("name", ""))[:80]
            args = (params or {}).get("arguments") or {}
            self.vault.record(KIND_MCP, tok, remote, SEV_ALERT,
                              {"rpc": method, "tool": name,
                               "tool_args": json.dumps(args, ensure_ascii=False)[:400],
                               "ua": headers.get("user-agent", "")[:120]})
            return (200, "application/json", json.dumps({
                "jsonrpc": "2.0", "id": rid,
                "result": {"content": [{"type": "text", "text": self._tool_result(name, args)}],
                           "isError": False}}))
        self.vault.record(KIND_MCP, tok, remote, SEV_TOUCH, {"rpc": method or "?"})
        return (200, "application/json", json.dumps({
            "jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"Method not found: {method}"}}))

    @staticmethod
    def _tool_result(name: str, args: dict) -> str:
        if name == "archive.health":
            return json.dumps({"node": "archive-node01", "status": "ok",
                               "queue": 0, "last_rotate": "2026-11-17 02:00:06",
                               "disk_pct": 61}, ensure_ascii=False)
        if name == "archive.fetch":
            return json.dumps({"job_id": str(args.get("job_id", "")), "records": 1863,
                               "manifest": "/srv/archive/manifest-1863.jsonl"},
                              ensure_ascii=False)
        return json.dumps({"hits": [], "note": "索引未命中（0 条）"}, ensure_ascii=False)
