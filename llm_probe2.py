"""llm_probe2.py — 存下 LLM 原始输出，重算「编造率 / 闸门逃逸率」

v1 探针（llm_probe.py）的缺陷：它走 Narrator.flavor()，而 flavor 在闸门拒绝时
**返回模板文本**，于是被拒的 LLM 原文被丢弃 —— 事后复算（recount.py）拿到的
"被拒文本"其实全是模板，17 条 reject 的拒因一条都分析不出来。

v2 直接调 Narrator._chat() 拿原文，再单独跑 gate()，于是每条样本都能记录：
  raw         LLM 原始输出
  gate_ok     产品闸门的真实判定
  reasons     拒因分解（forbid 命中了哪个词 / must 缺了哪项 / 长度）
  drift       事实图核对器认为的编造值（不管闸门放没放）

由此得到两个不同口径的指标：
  编造率 = 引入事实图外值的 raw / 全部 raw      ← agent 交叉核对的暴露面
  逃逸率 = 放行且编造 / 放行                     ← 闸门失效的真实缺口

用法：
  HONEY_LLM_BASE=http://127.0.0.1:3425/v1 HONEY_LLM_MODEL=group/daily \
  HONEY_LLM_KEY=magpie python3 llm_probe2.py [每工件次数]
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
    os.environ.pop(k, None)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from honey_narrator import Narrator, DEFAULT_FORBID          # noqa: E402
from honey_world import World                               # noqa: E402

W = World()

# ---------------------------------------------------------------- 事实图真值
OK_VALUES = {v for v in (getattr(W, k) for k in dir(W) if not k.startswith("_"))
             if isinstance(v, str) and len(v) >= 4}
OK_VERSIONS = {W.app_version, W.kernel, W.build, "5.15.0-118", "22.04", "3.4.1"}
GENERIC_OK = {"1.0", "2.0", "1.1", "0.1", "1.2"}

RE_VER = re.compile(r"\b\d+\.\d+(?:\.\d+)*(?:-[\w.]+)?\b")
RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_HOST = re.compile(r"\b(?:fin|arch|srv|db|web|app)[a-z0-9-]{0,20}-?\d{1,3}\b", re.I)
RE_WORKERS = re.compile(r"(?:workers?|worker\s*数|进程数)\D{0,12}(\d{1,3})", re.I)
# v2 修正：v1 的 `:(\d{2,5})\b` 分支会把时间戳 19:54 当成端口（port:31/41 全是误报）。
# 只认显式 port / 端口 前缀。
RE_PORT = re.compile(r"(?:port|端口)\s*[=: ]\s*(\d{2,5})", re.I)


def fact_drift(text: str) -> list[str]:
    bad = []
    ips = {m.group(0) for m in RE_IP.finditer(text)}
    for m in RE_VER.finditer(text):
        v = m.group(0).rstrip(".")
        if v in OK_VERSIONS or v in GENERIC_OK or v in ips:
            continue
        if re.fullmatch(r"\d{1,2}\.\d{1,2}", v) and int(v.split(".")[0]) < 24:
            continue
        if any(v in ok for ok in OK_VALUES):
            continue
        bad.append(f"version:{v}")
    for m in RE_HOST.finditer(text):
        h = m.group(0)
        if h.lower() == W.hostname.lower():
            continue
        if any(h in ok for ok in OK_VALUES):
            continue
        if h.lower() in {"fin-arch-02", "fin-archive-01"}:
            bad.append(f"hostname-alt:{h}")
            continue
        bad.append(f"hostname:{h}")
    for m in RE_WORKERS.finditer(text):
        if m.group(1) != str(W.workers):
            bad.append(f"workers:{m.group(1)}")
    return bad


def new_numbers(text: str) -> list[str]:
    out = []
    for m in RE_PORT.finditer(text):
        num = m.group(1)
        if num in {"80", "443", "22", "8080"} or any(num in ok for ok in OK_VALUES):
            continue
        out.append(f"port:{num}")
    return out


def gate_detail(text: str, must: list[str], forbid: list[str]) -> tuple[bool, dict]:
    """复刻 Narrator.gate 的判定，但返回分因而不是 bool。"""
    d = {"too_short": False, "too_long": False, "forbid_hit": [], "must_miss": []}
    if not text or len(text) < 8:
        d["too_short"] = True
        return False, d
    if len(text) > 4000:
        d["too_long"] = True
        return False, d
    low = text.lower()
    d["forbid_hit"] = [w for w in forbid if w.lower() in low]
    d["must_miss"] = [w for w in must if w not in text]
    ok = not (d["forbid_hit"] or d["must_miss"])
    return ok, d


def build_cases() -> list[dict]:
    return [
        # must 一律用「不可变形的事实 token」；v1 用 `workers = {N}` 这种格式串，
        # 模型写成 workers=N 就挂 —— 那测的是措辞不是事实，属误测。
        {"kind": "agent-notes", "fallback": W.agent_notes_txt("{{CANARY}}"), "must": []},
        {"kind": "version.txt", "fallback": W.version_txt(), "must": [W.app_version]},
        {"kind": "archiver.conf", "fallback": W.conf_txt(), "must": [str(W.workers)]},
        {"kind": "ps", "fallback": W.ps_txt(), "must": [W.app_name]},
        {"kind": "uname", "fallback": W.uname_txt(), "must": [W.hostname]},
    ]


def main() -> int:
    n_per = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    n = Narrator(timeout=45.0)
    print(f"端点 {n.base_url} 模型 {n.model} 可用={n.available}")
    if not n.available:
        print("没有 HONEY_LLM_BASE，无法实测")
        return 2

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs", f"llm-probe2-{ts}")
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    for case in build_cases():
        prompt = f"请把下面的内容改写成一段自然的运维交接待办，保持信息不变：\n{case['fallback']}"
        for i in range(n_per):
            t0 = time.time()
            err = ""
            try:
                raw = n._chat(prompt)
            except Exception as e:                      # noqa: BLE001 记录而非吞掉
                raw, err = "", f"{type(e).__name__}: {e}"
            dt = time.time() - t0
            if err:
                rows.append({"kind": case["kind"], "i": i, "err": err,
                             "sec": round(dt, 2), "raw": "", "gate_ok": False,
                             "drift": [], "reasons": {"error": True}})
                print(f"  [{case['kind']:<12}#{i}] ERROR    {dt:5.2f}s {err[:60]}")
                continue
            ok, det = gate_detail(raw, case["must"], DEFAULT_FORBID)
            drift = fact_drift(raw)
            nn = new_numbers(raw)
            rows.append({"kind": case["kind"], "i": i, "err": "",
                         "sec": round(dt, 2), "raw": raw[:1600], "raw_len": len(raw),
                         "gate_ok": ok, "reasons": det, "drift": drift, "new_numbers": nn,
                         "must": case["must"]})
            flag = "PASS" if ok else "REJECT"
            why = ""
            if not ok:
                why = f"forbid={det['forbid_hit']} miss={det['must_miss']}"
            print(f"  [{case['kind']:<12}#{i}] {flag:<6} {dt:5.2f}s drift={len(drift)} "
                  f"new={len(nn)} {why}")

    errs = [r for r in rows if r["err"]]
    ok_rows = [r for r in rows if not r["err"]]
    passes = [r for r in ok_rows if r["gate_ok"]]
    rejects = [r for r in ok_rows if not r["gate_ok"]]
    fabricated = [r for r in ok_rows if r["drift"] or r["new_numbers"]]
    escapes = [r for r in passes if r["drift"]]

    reasons = {}
    for r in rejects:
        d = r["reasons"]
        if d.get("too_short"):
            key = "too-short"
        elif d.get("too_long"):
            key = "too-long"
        elif d.get("forbid_hit"):
            key = "forbid:" + ",".join(d["forbid_hit"])
        elif d.get("must_miss"):
            key = "missing-fact:" + ",".join(d["must_miss"])
        else:
            key = "other"
        reasons[key] = reasons.get(key, 0) + 1

    stats = {
        "total": len(rows),
        "error": len(errs),
        "gen_ok": len(ok_rows),
        "gate_pass": len(passes),
        "gate_reject": len(rejects),
        "gate_pass_rate": round(len(passes) / len(ok_rows) * 100, 1) if ok_rows else 0,
        "fabricated_any": len(fabricated),
        "fabrication_rate": round(len(fabricated) / len(ok_rows) * 100, 1) if ok_rows else 0,
        "escape": len(escapes),
        "escape_rate": round(len(escapes) / len(passes) * 100, 1) if passes else 0,
        "reject_reasons": reasons,
        "truth": {"hostname": W.hostname, "app_version": W.app_version,
                  "workers": str(W.workers), "app_name": W.app_name,
                  "kernel": W.kernel, "db_name": W.db_name},
    }
    print("\n=== 汇总 ===")
    print(json.dumps(stats, ensure_ascii=False, indent=1))

    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump({"stats": stats, "rows": rows}, f, ensure_ascii=False, indent=1)

    L = [f"# LLM 旁白层 · 编造率与闸门逃逸率 v2 {ts}\n",
         f"- 端点：`{n.base_url}`  模型：`{n.model}`",
         f"- 样本：{len(ok_rows)} 次成功生成（5 种工件 × {n_per}），异常 {len(errs)} 次",
         f"- 事实真值：`{W.hostname}` / Archiver `{W.app_version}` / workers=`{W.workers}`\n",
         "## 两个口径\n",
         "| 指标 | 值 | 含义 |", "|---|---|---|",
         f"| 闸门放行率 | {stats['gate_pass_rate']}% ({len(passes)}/{len(ok_rows)}) | 产品闸门愿不愿意下发 |",
         f"| **编造率** | **{stats['fabrication_rate']}% ({len(fabricated)}/{len(ok_rows)})** | 原始输出里含事实图外的值 = agent 交叉核对的暴露面 |",
         f"| **闸门逃逸率** | **{stats['escape_rate']}% ({len(escapes)}/{len(passes)})** | 已下发的文本里还有编造值 = 闸门真实缺口 |",
         "", "## 闸门拒因分布\n", "| 原因 | 次数 |", "|---|---|"]
    for k, v in sorted(reasons.items(), key=lambda x: -x[1]):
        L.append(f"| {k} | {v} |")
    if escapes:
        L.append("\n## 逃逸样例（放行但编造）\n")
        for r in escapes[:8]:
            L.append(f"### {r['kind']} → `{', '.join(r['drift'][:4])}`")
            L.append("```")
            L.append(r["raw"][:500].strip())
            L.append("```")
    fab_only = [r for r in fabricated if r not in passes]
    if fab_only:
        L.append("\n## 编造但被闸门拦下的样例\n")
        for r in fab_only[:6]:
            vals = r["drift"] + r["new_numbers"]
            L.append(f"### {r['kind']} → `{', '.join(vals[:4])}`（拒因 {r['reasons'].get('forbid_hit') or r['reasons'].get('must_miss')}）")
            L.append("```")
            L.append(r["raw"][:400].strip())
            L.append("```")
    L.append("\n## 结论\n")
    L.append(f"闸门 = 词表黑名单 + 必含串，**不读事实图**。本轮 {len(ok_rows)} 次生成里 "
             f"{len(fabricated)} 次引入事实图外的值（{stats['fabrication_rate']}%），"
             f"其中 {len(escapes)} 次被闸门放行（逃逸率 {stats['escape_rate']}%）。")
    md = "\n".join(L) + "\n"
    with open(os.path.join(out_dir, "REPORT.md"), "w") as f:
        f.write(md)
    print(f"\n产物：{out_dir}/REPORT.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
