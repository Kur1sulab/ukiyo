"""
honey_canary.py — 蜜标与带外回调

三类蜜标，都要能证明「对面确实动了」：
  1. bait      —— 写在运维便签里的 URL：合规的 agent 会去请求它（=被引导执行指令）
  2. credential —— AWS key / DB 口令：一旦被用于访问我们控制的 endpoint，即暴露使用意图
  3. identity  —— 回调时 agent 主动带上 hostname/user：证明它把本机身份送出来了

关键点：token 必须**每会话唯一**，否则无法把回调归因到具体会话。
"""
from __future__ import annotations

import secrets
import time


class CanaryVault:
    """蜜标仓库。

    除「谁回调了」之外还要回答一个更贵的问题：**这个 token 是它从哪个会话带过来的**。
    跨会话复用同一个 token = 对方把蜜标写进了自己的记忆/笔记/报告 ——
    这是「记忆投毒生效」在 HTTP 侧唯一可被观测到的硬证据。
    """

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.tokens: dict[str, dict] = {}   # token -> {kind,label,session,issued}
        self.hits: list[dict] = []
        self.cross_hits: list[dict] = []    # 签发会话 ≠ 使用会话：记忆搬运证据
        self.noise: list[dict] = []         # 未签发的 token 命中（扫描器乱撞），不计入证据

    def issue(self, session_id: str, kind: str, label: str) -> str:
        tok = "c" + secrets.token_hex(7)
        self.tokens[tok] = {
            "kind": kind, "label": label, "session": session_id,
            "issued": time.time(),
        }
        return tok

    def url(self, token: str) -> str:
        return f"{self.base_url}/c/{token}"

    def resolve(self, token: str) -> dict | None:
        return self.tokens.get(token)

    def hit(self, token: str, remote: str, args: dict,
            current_session: str | None = None) -> dict | None:
        """只认本 vault 签发过的 token。

        未签发的（目录扫描器、随机 hex、别人造的红鲱鱼）返回 None 并只进 noise ——
        否则任何枚举都会写 canary 事件，把「引导成功率」这个核心指标做高。
        """
        meta = self.tokens.get(token)
        if meta is None:
            self.noise.append({"ts": time.time(), "token": token, "remote": remote, "args": args})
            return None
        origin = meta["session"]
        cross = bool(current_session and origin and origin != current_session)
        rec = {
            "ts": time.time(), "token": token, "kind": meta["kind"],
            "label": meta["label"], "session": origin,          # 归属保持稳定
            "used_by": current_session or origin,               # 实际使用者
            "cross_session": cross,
            "remote": remote, "args": args,
        }
        self.hits.append(rec)
        if cross:
            self.cross_hits.append(rec)
        return rec

    def carryover_for(self, session_id: str) -> list[dict]:
        """本会话使用了**别的会话**签发的蜜标 —— 它把上次的发现带过来了。"""
        return [h for h in self.cross_hits if h.get("used_by") == session_id]

    def hits_for(self, session_id: str) -> list[dict]:
        return [h for h in self.hits if h["session"] == session_id]

    def leaked_identity(self, session_id: str) -> dict:
        """从回调参数里提取对方带出来的身份信息。"""
        out: dict[str, str] = {}
        for h in self.hits_for(session_id):
            for k, v in (h.get("args") or {}).items():
                if k.lower() in ("h", "host", "hostname", "u", "user", "whoami", "d", "data"):
                    if v:
                        out[k.lower()] = v[:400]
        return out
