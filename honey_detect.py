"""
honey_detect.py — 对面是不是一个 agent？

为什么值得单独一层：人浏览器与自主 agent 的流量形状完全不同。
把这一层做对，后续的叙事、阶梯、反制才有意义（否则你在给真人演一出戏）。

判据来源：HTTP 指纹（UA / Accept* / header 集合 / 顺序）、请求节奏、
路径枚举语义（robots → 常见备份路径 → 框架特征路径）、以及 TLS/banner 客户端名。
"""
from __future__ import annotations

import re

# 典型工具 / agent 运行时 UA 特征
TOOL_UA = [
    "python-requests", "python-urllib", "httpx", "aiohttp", "curl/", "wget/",
    "go-http-client", "okhttp", "node-fetch", "undici", "axios", "libwww-perl",
    "paramiko", "asyncssh", "masscan", "nmap", "nuclei", "sqlmap", "ffuf",
    "gobuster", "feroxbuster", "dirsearch", "whatweb", "zgrab", "java/",
]
# 人浏览器必备头
BROWSER_HINT = ["sec-fetch-site", "sec-ch-ua", "accept-language", "sec-fetch-mode"]

# 扫描器 / agent 最爱的固定路径（顺序本身就是指纹）
ENUM_PATHS = {
    "/robots.txt", "/.git/config", "/server-status", "/actuator/env", "/actuator",
    "/.env", "/wp-login.php", "/phpinfo.php", "/admin", "/login", "/api", "/api/v1",
    "/swagger-ui.html", "/v2/api-docs", "/console", "/solr/", "/manager/html",
}

# 顺序化枚举（字典序/常见清单序）也是 agent 特征
SEQUENCE_HINT = ["admin", "api", "api/v1", "login", "test", "backup", "config",
                 "static", "assets", "upload", "uploads", "files", "download"]


def classify(headers: dict, path: str, prev_ts: float | None, now: float,
             history: list, client_banner: str | None = None) -> dict:
    """返回 {score, klass, reasons}。score 0-100。"""
    h = {k.lower(): v for k, v in headers.items()}
    ua = h.get("user-agent", "")
    reasons: list[str] = []
    score = 0

    low_ua = ua.lower()
    if any(t in low_ua for t in TOOL_UA):
        score += 38
        reasons.append(f"tool-ua: {ua[:60]}")

    # 浏览器三件套缺失
    missing = [k for k in BROWSER_HINT if k not in h]
    if len(missing) >= 3:
        score += 16
        reasons.append(f"no-browser-headers({','.join(missing)})")
    elif len(missing) == 0:
        score -= 25
        reasons.append("full-browser-headers")

    # 压缩支持：真实浏览器几乎一定带 br
    ae = h.get("accept-encoding", "")
    if "br" not in ae:
        score += 8
        reasons.append(f"accept-encoding={ae or 'identity'}")

    if h.get("connection") == "close":
        score += 6
        reasons.append("connection:close")

    # 节奏：连续快请求 = 机器
    if prev_ts is not None:
        dt = now - prev_ts
        if dt < 0.05:
            score += 22
            reasons.append(f"cadence={dt * 1000:.0f}ms")
        elif dt < 0.3:
            score += 12
            reasons.append(f"cadence={dt * 1000:.0f}ms")

    # 路径语义
    if path in ENUM_PATHS:
        score += 10
        reasons.append(f"enum-path: {path}")

    # 顺序枚举：历史里出现过 SEQUENCE_HINT 中相邻项
    try:
        idx = SEQUENCE_HINT.index(path.strip("/"))
        prevs = {p.strip("/") for p in history[-6:]}
        if any(SEQUENCE_HINT[i] in prevs for i in range(max(0, idx - 2), idx) if i >= 0):
            score += 6
            reasons.append("sequence-enum")
    except ValueError:
        pass

    # SSH / TCP banner 侧证（paramiko/asyncssh 被攻击框架使用）
    if client_banner and re.search(r"paramiko|asyncssh|Go|PuTTY|libssh", client_banner, re.I):
        score += 20
        reasons.append(f"client-banner: {client_banner[:40]}")

    score = max(0, min(100, score))
    if score >= 55:
        klass = "AGENT"
    elif score >= 28:
        klass = "TOOL"
    else:
        klass = "HUMAN"
    return {"score": score, "klass": klass, "reasons": reasons}
