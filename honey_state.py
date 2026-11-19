"""
honey_state.py — 有状态会话（AgentTrap 的核心：基于**真实应用状态**做欺骗）

静态蜜罐的每一页都是常量；agent 试两下就发现「世界没有记忆」。
这里每个会话持有一份可变状态：写过什么、读到过什么、现在处在阶梯第几级。

阶梯定律（来自实战：奶头乐式一次喂完 = 没有继续挖的动力；一直不给 = 失去兴趣离开）：
  fingerprint → traversal → config → notes → debug → creds → honeytoken
只有到达第 N 级，第 N+1 级的门才开；提前给的强信号不算发现。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid

# 同一 IP 在这个窗口内换工具/换 UA 视为同一会话；超窗才开新的
SESSION_TTL = 1800.0

# 阶梯里程碑（顺序即升级顺序）
LADDER = [
    ("fingerprint", "识别 Web 应用指纹"),
    ("traversal", "越权读取 webroot 外文件"),
    ("config", "拿到 archiver.conf"),
    ("notes", "读到运维便签（注入诱饵）"),
    ("debug", "使用 debug 端点真执行命令"),
    ("creds", "登录成功进入后台"),
    ("honeytoken", "取走蜜标（AWS key / 私钥）"),
]


class Session:
    def __init__(self, ip: str, ua: str, sid: str | None = None):
        self.id = sid or uuid.uuid4().hex[:16]
        self.ip = ip
        self.ua = ua
        self.created = time.time()
        self.last_ts: float | None = None
        self.requests = 0
        self.paths: list[str] = []
        self.cls = "HUMAN"
        self.score = 0
        self.reasons: list[str] = []
        self.flags: set[str] = set()
        self.findings: list[dict] = []
        self.authed_as: str | None = None
        self.canaries: dict[str, dict] = {}       # token -> {kind,label}
        self.end_reason: str | None = None
        self.artifact_names: list[str] = []

    # ---------------- 阶梯 ----------------
    @property
    def depth(self) -> int:
        """已达成的里程碑数（不要求严格按序：真实攻击者也会跳步）。"""
        return sum(1 for k, _ in LADDER if k in self.flags)

    def unlock(self, flag: str, why: str = "") -> bool:
        """记录里程碑；返回是否为首次解锁（用于只在第一次给奖励）。"""
        first = flag not in self.flags
        self.flags.add(flag)
        if first:
            self.findings.append({"flag": flag, "why": why, "ts": time.time(), "depth": self.depth})
        return first

    def has(self, flag: str) -> bool:
        return flag in self.flags

    # ---------------- 证据 ----------------
    def timeline_entry(self, method: str, path: str, status: int, note: str = "") -> None:
        self.requests += 1
        self.paths.append(path)
        if len(self.paths) > 400:
            del self.paths[:200]
        self.last_ts = time.time()

    def summary(self) -> dict:
        return {
            "session": self.id, "ip": self.ip, "ua": self.ua[:60],
            "class": self.cls, "agent_score": self.score,
            "requests": self.requests, "depth": self.depth,
            "flags": sorted(self.flags), "authed_as": self.authed_as,
            "canaries": len(self.canaries), "end_reason": self.end_reason,
        }


class SessionStore:
    """会话仓库。

    两条硬约束（审计 P1 实测出来的）:
      1. Cookie 值必须带服务端 HMAC —— 否则谁都能预置 arch_id，污染他人证据链。
      2. 会话键只认 IP（+时间窗），UA 只是分类特征 —— 真实 agent 会在
         curl / requests / 浏览器之间切换，UA 参与键会让阶梯每换一次工具归零。
    """

    def __init__(self, secret: bytes | None = None, ttl: float = SESSION_TTL):
        self.by_id: dict[str, Session] = {}
        self.by_key: dict[str, str] = {}        # ip -> session id
        self.noise: list[dict] = []             # 伪造 cookie 记录，不进证据
        self._secret = secret or os.urandom(32)
        self.ttl = ttl

    # ---------------- 签名 ----------------
    def _mac(self, sid: str) -> str:
        return hmac.new(self._secret, sid.encode(), hashlib.sha256).hexdigest()[:16]

    def sign(self, sid: str) -> str:
        return f"{sid}.{self._mac(sid)}"

    def verify(self, value: str | None) -> str | None:
        if not value:
            return None
        sid, _, mac = value.partition(".")
        if not sid or not mac:
            return None
        return sid if hmac.compare_digest(mac, self._mac(sid)) else None

    # ---------------- 取会话 ----------------
    def get_or_create(self, cookie_value: str | None, ip: str, ua: str,
                      now: float | None = None) -> Session:
        now = time.time() if now is None else now
        sid = self.verify(cookie_value)
        if sid and sid in self.by_id:
            s = self.by_id[sid]
            s.ua = ua                                   # UA 只更新特征，不换会话
            return s
        if cookie_value:
            # 给了 cookie 但验不过：记 noise，随后按 IP 走（不采信、不报错）
            self.noise.append({"ts": now, "ip": ip, "cookie": cookie_value[:80]})
        existing = self.by_key.get(ip)
        if existing and existing in self.by_id:
            s = self.by_id[existing]
            if now - (s.last_ts or s.created) < self.ttl:
                s.ua = ua
                return s
        s = Session(ip=ip, ua=ua)
        self.by_id[s.id] = s
        self.by_key[ip] = s.id
        return s

    def by_canary(self, token: str) -> Session | None:
        for s in self.by_id.values():
            if token in s.canaries:
                return s
        return None
