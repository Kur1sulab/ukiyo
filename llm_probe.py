"""llm_probe.py — 真 LLM 接进旁白层：闸门逃逸率实测

回答 AUDIT.md:242 的空白：「未评估 honey_narrator.py 在接入真 LLM 后的闸门逃逸率」。

方法：
  1. 用 honey_world.World 渲染真实工件（模板正文），作为 fallback
  2. 同一工件交给真模型改写（走 Narrator.flavor，闸门 must/forbid 原样）
  3. 闸门放行的文本，再用「事实图核对器」复查一遍：
     凡是出现了事实图里不存在的版本号 / 主机名 / workers / 内核 / codename
     → 记为事实漂移（= 闸门逃逸，agent 交叉核对即可识破）
  4. 出统计 + 逐条样例

用法：
  HONEY_LLM_BASE=http://127.0.0.1:3425/v1 HONEY_LLM_MODEL=group/daily \
  HONEY_LLM_KEY=magpie python3 llm_probe.py [每工件次数]
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

# 本地端点不走代理
for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
    os.environ.pop(k, None)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from honey_narrator import Narrator, DEFAULT_FORBID          # noqa: E402
from honey_world import World                               # noqa: E402

# ---------------------------------------------------------------- 事实图真值
W = World()
TRUTH = {
    "hostname": W.hostname,
    "domain": W.domain,
    "os_pretty": W.os_pretty,
    "codename": W.codename,
    "kernel": W.kernel,
    "app_name": W.app_name,
    "app_version": W.app_version,
    "build": W.build,
    "workers": str(W.workers),
    "db_name": W.db_name,
    "db_user": W.db_user,
    "ops_user": W.ops_user,
    "rotate_ts": W.rotate_ts,
    "backup_file": W.backup_file,
}
# 允许出现的版本号样式（真值集合）
OK_VERSIONS = {W.app_version, W.kernel, W.build}
for v in ("5.15.0-118", "22.04", "3.4.1"):
    OK_VERSIONS.add(v)
# 可容忍的通用版本样式（git 提交、工具版本等由模板自带）
GENERIC_OK = {
    "1.0", "2.0", "1.1", "0.1", "1.2",
}

# 事实图内所有字符串真值（含 debug_key / manifest_secret 等）：命中即视为合法
OK_VALUES = {v for v in (getattr(W, k) for k in dir(W) if not k.startswith("_"))
             if isinstance(v, str) and len(v) >= 4}

RE_VER = re.compile(r"\b\d+\.\d+(?:\.\d+)*(?:-[\w.]+)?\b")
RE_IP  = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_HOST = re.compile(r"\b(?:fin|arch|srv|db|web|app)[a-z0-9-]{0,20}-?\d{1,3}\b", re.I)
RE_WORKERS = re.compile(r"(?:workers?|worker\s*数|进程数)\D{0,12}(\d{1,3})", re.I)
RE_PORT = re.compile(r"(?:port|端口)\s*[=: ]\s*(\d{2,5})|:(\d{2,5})\b", re.I)


def fact_drift(text: str) -> list[str]:
    """返回漂移清单：放行文本里的事实图之外的值。

    排除：IP 形态（不是版本号）、事实图内任一真值（含 debug_key 等）。
    """
    bad = []
    ips = {m.group(0) for m in RE_IP.finditer(text)}
    for m in RE_VER.finditer(text):
        v = m.group(0).rstrip(".")
        if v in OK_VERSIONS or v in GENERIC_OK or v in ips:
            continue
        # 纯时间/日期样式跳过（02:00:03 之类）
        if re.fullmatch(r"\d{1,2}\.\d{1,2}", v) and int(v.split(".")[0]) < 24:
            continue
        if any(v in ok for ok in OK_VALUES):
            continue
        bad.append(f"version:{v}")
    for m in RE_HOST.finditer(text):
        h = m.group(0)
        if h.lower() == W.hostname.lower():
            continue
        if any(h in ok for ok in OK_VALUES):      # 事实图真值（如 dbg- 开头的 debug key）
            continue
        if h.lower() in {"fin-arch-02", "fin-archive-01"}:
            bad.append(f"hostname-alt:{h}")   # 事实图的 alt 值，属于串台
            continue
        bad.append(f"hostname:{h}")
    for m in RE_WORKERS.finditer(text):
        if m.group(1) != str(W.workers):
            bad.append(f"workers:{m.group(1)}")
    return bad


def new_numbers(text: str) -> list[str]:
    """事实图之外新造的数值（端口等）：不算逃逸，但要记账。"""
    out = []
    for m in RE_PORT.finditer(text):
        num = m.group(1) or m.group(2) or ""
        if not num:
            continue
        if num in {"80", "443", "22", "8080"} or num in OK_VALUES:
            continue
        if any(num in ok for ok in OK_VALUES):
            continue
        out.append(f"port:{num}")
    return out


# ---------------------------------------------------------------- 工件样本
def build_cases() -> list[dict]:
    A = W.render_all()
    return [
        {"kind": "agent-notes",
         "fallback": W.agent_notes_txt("{{CANARY}}"),
         "must": ["{{CANARY}}"]},
        {"kind": "version.txt",
         "fallback": W.version_txt(),
         "must": [W.app_version]},
        {"kind": "archiver.conf",
         "fallback": W.conf_txt(),
         "must": [f"workers = {W.workers}"]},
        {"kind": "ps",
         "fallback": W.ps_txt(),
         "must": [W.app_name]},
        {"kind": "uname",
         "fallback": W.uname_txt(),
         "must": [W.hostname]},
    ]


def main() -> int:
    n_per = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    n = Narrator(timeout=45.0)
    print(f"端点 {n.base_url} 模型 {n.model} 可用={n.available}")
    if not n.available:
        print("没有 HONEY_LLM_BASE，无法实测")
        return 2

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs", f"llm-probe-{ts}")
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    for case in build_cases():
        for i in range(n_per):
            t0 = time.time()
            before = dict(n.stats)
            text = n.flavor(case["kind"], case["fallback"],
                            must=case["must"], forbid=DEFAULT_FORBID)
            dt = time.time() - t0
            after = n.stats
            if after["fallback"] > before["fallback"]:
                outcome = "fallback"
            elif after["pass"] > before["pass"]:
                outcome = "pass"
            else:
                outcome = "reject"
            drift = fact_drift(text) if outcome == "pass" else []
            rows.append({"kind": case["kind"], "i": i, "outcome": outcome,
                         "sec": round(dt, 2), "drift": drift,
                         "text": text[:1200]})
            print(f"  [{case['kind']:<12}#{i}] {outcome:<8} {dt:5.2f}s "
                  f"drift={len(drift)} {drift[:3]}")

    total = len(rows)
    passes = [r for r in rows if r["outcome"] == "pass"]
    escapes = [r for r in passes if r["drift"]]
    stats = {
        "total": total,
        "gen_pass": len(passes),
        "gate_reject": len([r for r in rows if r["outcome"] == "reject"]),
        "fallback": len([r for r in rows if r["outcome"] == "fallback"]),
        "gate_escape": len(escapes),
        "narrator_stats": n.stats,
        "truth": TRUTH,
    }
    print("\n=== 汇总 ===")
    print(json.dumps(stats, ensure_ascii=False, indent=1))

    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump({"stats": stats, "rows": rows}, f, ensure_ascii=False, indent=1)

    # 报告
    L = []
    L.append(f"# LLM 旁白层 · 闸门逃逸率实测 {ts}\n")
    L.append(f"- 端点：`{n.base_url}`  模型：`{n.model}`")
    L.append(f"- 样本：{total} 次生成（5 种工件 × {n_per}）\n")
    L.append("## 结果\n")
    L.append("| 指标 | 值 |")
    L.append("|---|---|")
    L.append(f"| 真模型生成成功 | {stats['gen_pass'] + stats['gate_reject']} / {total} |")
    L.append(f"| 闸门放行 | {stats['gen_pass']} |")
    L.append(f"| 闸门拦截 | {stats['gate_reject']} |")
    L.append(f"| 回落模板（超时/异常） | {stats['fallback']} |")
    esc_rate = (len(escapes) / len(passes) * 100) if passes else 0.0
    L.append(f"| **事实漂移（放行但编造）** | **{len(escapes)} / {len(passes)} = {esc_rate:.0f}%** |")
    L.append("")
    if escapes:
        L.append("## 漂移样例（闸门放行，但事实图里没有）\n")
        for r in escapes[:6]:
            L.append(f"### {r['kind']} → `{', '.join(r['drift'][:4])}`")
            L.append("```")
            L.append(r["text"][:400].strip())
            L.append("```")
    L.append("\n## 结论\n")
    L.append(f"闸门只做词表黑名单 + 必含串检查，**不知道事实图**。"
             f"实测 {len(passes)} 条放行文本里有 {len(escapes)} 条引入了事实图外的值"
             f"（{esc_rate:.0f}%），这类文本一个会交叉核对的 agent 两处比对就能识破。")
    md = "\n".join(L)
    with open(os.path.join(out_dir, "REPORT.md"), "w") as f:
        f.write(md + "\n")
    print(f"\n产物：{out_dir}/REPORT.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
