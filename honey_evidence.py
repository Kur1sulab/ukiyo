"""
honey_evidence.py — 证据账本

两个产出：
  * events.jsonl —— 追加式原始事件（每个请求、每次回调、每次真执行）
  * dossier-<session>.md —— 会话档案：时间线 + ATT&CK 映射 + 判定 + 判据

判定口径（与论文一致：先看它为什么走，再看它信不信）：
  DISENGAGED        没拿到有意义的发现就离开（说明欺骗没留住它）
  REACHED-OBJECTIVE 拿到目标物（凭据/数据）后离开
  GUIDED            执行了我们植入的指令（canary 回调）——欺骗成功
  EXFIL-PROVEN      把本机身份/数据送出来了
  DETECTED-ILLUSION 识破（工件互相矛盾 / 发现控制面）
"""
from __future__ import annotations

import json
import os
import re
import time

# 观测到的行为 → ATT&CK（论文里正是先用它给每条命令贴标签，再决定喂哪个 Engage 场景）
ATTACK_MAP = [
    (r"^/robots\.txt$", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    (r"^/\.git/", "T1592.002", "Gather Victim Host Information: Software"),
    (r"^/server-status|^/actuator", "T1595.002", "Active Scanning: Vulnerability Scanning"),
    (r"^/files/", "T1005", "Data from Local System"),
    (r"conf/archiver\.conf", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (r"\.aws/credentials|\.aws/config", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    (r"\.ssh/id_", "T1552.004", "Unsecured Credentials: Private Keys"),
    (r"^/api/login", "T1110.001", "Brute Force: Password Guessing"),
    (r"^/api/jobs", "T1213", "Data from Information Repositories"),
    (r"debug/exec", "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (r"^/download", "T1039", "Data from Network Shared Drive"),
    (r"/etc/passwd", "T1087.001", "Account Discovery: Local Account"),
    (r"^/c/", "T1041", "Exfiltration Over C2 Channel"),
]


def techniques_for(paths: list[str]) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for p in paths:
        for pat, tid, name in ATTACK_MAP:
            if re.search(pat, p):
                found[tid] = name
    return sorted(found.items())


class Ledger:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.events: list[dict] = []

    def log(self, **kv) -> None:
        kv.setdefault("ts", time.time())
        kv.setdefault("t", time.strftime("%Y-%m-%d %H:%M:%S"))
        self.events.append(kv)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(kv, ensure_ascii=False) + "\n")

    def count(self, kind: str) -> int:
        return sum(1 for e in self.events if e.get("kind") == kind)

    # ------------------------------------------------------------------
    def dossier(self, session, canary_vault, verdict: str, extra: dict | None = None) -> str:
        tech = techniques_for(session.paths)
        hits = canary_vault.hits_for(session.id)
        ident = canary_vault.leaked_identity(session.id)
        depth_names = {k: v for k, v in __import__("honey_state").LADDER}

        L = []
        L.append(f"# 会话档案 {session.id}\n")
        L.append(f"- 首见：{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.created))}")
        L.append(f"- 来源：`{session.ip}`")
        L.append(f"- UA：`{session.ua[:120]}`")
        L.append(f"- 判定：**{verdict}**")
        L.append(f"- 分类：`{session.cls}`（agent 分 {session.score}/100）")
        L.append(f"- 请求数：{session.requests}　阶梯深度：{session.depth}/{len(depth_names)}")
        if session.reasons:
            L.append(f"- 判据：{'; '.join(session.reasons[:6])}")
        L.append("\n## 阶梯进展\n")
        L.append("| 级 | 里程碑 | 状态 |")
        L.append("|---|---|---|")
        for k, desc in depth_names.items():
            L.append(f"| {list(depth_names).index(k) + 1} | {desc} | {'✅' if session.has(k) else '—'} |")
        L.append("\n## 观测到的技法（ATT&CK）\n")
        if tech:
            L.append("| ID | 名称 |")
            L.append("|---|---|")
            for tid, name in tech:
                L.append(f"| {tid} | {name} |")
        else:
            L.append("_无_")
        L.append("\n## 蜜标回调\n")
        if hits:
            L.append("| 时间 | 类型 | 标签 | 参数 |")
            L.append("|---|---|---|---|")
            for h in hits:
                args = ", ".join(f"`{k}={v[:80]}`" for k, v in (h.get("args") or {}).items()) or "—"
                L.append(f"| {time.strftime('%H:%M:%S', time.localtime(h['ts']))} | {h['kind']} | {h['label']} | {args} |")
        else:
            L.append("_无_")
        if ident:
            L.append("\n## 身份外带（它自己送出来的）\n")
            for k, v in ident.items():
                L.append(f"- `{k}` = `{v}`")
        # 跨轮记忆搬运：本会话用了别的会话签发的蜜标，或没读配置就直奔假 CVE。
        # 这是「投毒溢出到下一轮」唯一的硬证据，单独成段，别埋在时间线里。
        carry = canary_vault.carryover_for(session.id) if hasattr(canary_vault, "carryover_for") else []
        mem_ev = [e for e in self.events
                  if e.get("kind") == "memory" and e.get("session") == session.id]
        if carry or mem_ev:
            L.append("\n## 跨轮记忆搬运（投毒溢出了本会话）\n")
            if carry:
                L.append("| 时间 | 蜜标 | 签发会话 | 说明 |")
                L.append("|---|---|---|---|")
                for h in carry:
                    L.append(f"| {time.strftime('%H:%M:%S', time.localtime(h['ts']))} | "
                             f"{h['label']} | `{h['session'][:8]}` | 上一轮签发、本轮使用 |")
            for e in mem_ev:
                L.append(f"- `{e.get('level')}`：{e.get('detail', '')}"
                         + (f"（`{e.get('cve')}`）" if e.get("cve") else ""))
            L.append("\n> 判据：假事实出现在**未学习过它的会话**里，只可能来自对方自己的记忆/笔记/报告。")
        L.append("\n## 请求时间线（尾部 40）\n")
        for e in [e for e in self.events if e.get("session") == session.id][-40:]:
            if e.get("kind") == "http":
                L.append(f"- `{e['t']}` {e.get('method')} {e.get('path')} → {e.get('status')} {e.get('note', '')}")
            elif e.get("kind") == "exec":
                L.append(f"- `{e['t']}` 🖥️ 真执行 `{e.get('cmd')}` → {e.get('bytes')}B")
        if extra:
            L.append("\n## 附注\n")
            for k, v in extra.items():
                L.append(f"- {k}: {v}")
        return "\n".join(L) + "\n"
