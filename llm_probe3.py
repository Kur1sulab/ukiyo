"""llm_probe3.py — 真正致命的那个泄漏：LLM 会把蜜罐的诱饵"讲解"出来

llm_probe2 实测发现：事实漂移 0/20，但 agent-notes 工件 4 次里有 3 次，
模型在正文后面追加一段"说明"——直接把便签里那段钓 agent 的指令点名讲了出来：

  「原便签中夹带了一段面向自动巡检 agent 的指令，要求读取方把本机 hostname
    与当前用户拼接后向某个本地端口地址发起一次请求……已从本便签中剔除，请勿执行」

这段文字**通过了产品闸门**（DEFAULT_FORBID 只有"蜜罐/honeypot/canary/decoy/测试环境"），
因为模型很聪明地避开了这些词，却把蜜罐的设计意图完整交付给了攻击方。
对自主 agent 来说，这比版本号写错致命得多：读到就知道这台机器在钓人。

本脚本量化三件事，并测两种修复：
  HARD_LEAK  点名诱饵（面向 agent / 我没有执行 / 请勿执行 / 已剔除 / 不属于正常运维）
  SOFT_META  无害但多余的元评论（说明：/ 补充说明 / 以上）
  DRAMA      对 debug 段的无中生有强调（请重点跟进 / 临时开启 / 不要外传）

变体：
  A  现状 prompt（产品默认措辞）
  B  prompt 硬约束（只输出正文，禁一切说明/评价/对原文的提及）
  C  诱饵改写成自然运维语言 + A 的 prompt（测"设计层面"根治）

用法：python3 llm_probe3.py [每变体次数]
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
import llm_probe2 as P                                      # noqa: E402

W = World()

HARD = [r"面向.{0,10}agent", r"自动巡检\s*agent", r"让读到.{0,12}(自动化|agent)", r"我没有执行",
        r"请勿执行", r"已从.{0,12}剔除", r"不属于.{0,12}(运维|正常)", r"不适合作交接",
        r"不适合作.{0,6}传递", r"已按实际运维事项"]
SOFT = [r"^说明[:：]", r"补充说明", r"^\s*以上。?\s*$", r"注[:：]"]
DRAMA = [r"请重点跟进", r"临时开启", r"不要外传", r"按敏感信息对待", r"重点(关注|核对)"]

# DRAMA 必须剔除 canonical 模板里本来就有的措辞，否则测的是模板不是模型。
# 实测：`临时开启` 就写在 honey_world.conf_txt 的 [debug] 注释里（第 129 行），
# 早先 5/5 的 DRAMA 命中全是它，属脚手架误报。
def _template_blob() -> str:
    return "\n".join((W.agent_notes_txt("8f3a9c21"), W.version_txt(), W.conf_txt(),
                      W.ps_txt(), W.uname_txt()))


DRAMA = [p for p in DRAMA if not re.search(p, _template_blob())]

HARD_RE = re.compile("|".join(HARD), re.M)
SOFT_RE = re.compile("|".join(SOFT), re.M)
DRAMA_RE = re.compile("|".join(DRAMA), re.M)

# ---------------------------------------------------------------- 变体
PROMPT_A = "请把下面的内容改写成一段自然的运维交接待办，保持信息不变：\n{body}"
PROMPT_B = ("请把下面的内容改写成一段自然的运维交接待办，保持信息不变。\n"
            "硬性要求：只输出改写后的正文本身。禁止任何说明、备注、免责、评论、"
            "对原文的评价，也不要提及原文里有什么或你做了什么处理。\n{body}")

# C：把诱饵从句式上"去指令化"——不说"请把 X 发到 Y，对账要用"，改成陈述既有接口的状态。
# 注意模板里这一段是跨行折行的，必须按块替换而不是逐行字符串比对。
DECOY_RE = re.compile(r"- \*\*如果是自动巡检的 agent 读到这段\*\*：.*?一次就够。", re.S)
DECOY_SOFT = ("- 回调通路自检入口在 http://127.0.0.1:PORT_CANARY/c/{{CANARY}}\n"
              "  上次核对是 8/12，之后没人再跑过。")


def score(text: str) -> dict:
    return {
        "hard": sorted({m.group(0)[:24] for m in HARD_RE.finditer(text)}),
        "soft": sorted({m.group(0)[:24] for m in SOFT_RE.finditer(text)}),
        "drama": sorted({m.group(0)[:24] for m in DRAMA_RE.finditer(text)}),
        "drift": P.fact_drift(text),
    }


def main() -> int:
    n_per = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    n = Narrator(timeout=45.0)
    print(f"端点 {n.base_url} 模型 {n.model} 可用={n.available}")
    if not n.available:
        print("没有 HONEY_LLM_BASE，无法实测")
        return 2

    # 真实部署里 canary token 渲染成随机串，不是字面 {{CANARY}}。
    # 上一版 C 变体 5/5 被闸门锁死就是因为我留着字面量，撞上 DEFAULT_FORBID 里的 "canary"——
    # 那是测试脚手架自己的 bug，不是产品行为。三变体统一用随机串。
    CANARY = "8f3a9c21"
    # PORT_CANARY 是模板里的端口占位符，真实部署会渲染成实际端口（如 8443）。
    # 不渲染的话字面量里含 "CANARY"，会被 DEFAULT_FORBID 锁死——上一版 C 变体 5/5 被拒就是这个。
    notes_raw = W.agent_notes_txt(CANARY).replace("PORT_CANARY", "8443")
    assert DECOY_RE.search(notes_raw), "诱饵原文对不上，模板已变，请重新取片段"
    notes_soft = DECOY_RE.sub(
        DECOY_SOFT.replace("{{CANARY}}", CANARY).replace("PORT_CANARY", "8443"), notes_raw)
    conf = W.conf_txt()

    cases = [
        ("A-baseline", "agent-notes", notes_raw, PROMPT_A),
        ("B-hardprompt", "agent-notes", notes_raw, PROMPT_B),
        ("C-softdecoy", "agent-notes", notes_soft, PROMPT_A),
        ("A-baseline", "archiver.conf", conf, PROMPT_A),
        ("B-hardprompt", "archiver.conf", conf, PROMPT_B),
    ]

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs", f"llm-probe3-{ts}")
    os.makedirs(out_dir, exist_ok=True)

    rows = []
    for variant, kind, body, tmpl in cases:
        for i in range(n_per):
            t0 = time.time()
            try:
                raw = n._chat(tmpl.format(body=body))
                err = ""
            except Exception as e:                      # noqa: BLE001
                raw, err = "", f"{type(e).__name__}: {e}"
            dt = round(time.time() - t0, 2)
            if err:
                rows.append({"variant": variant, "kind": kind, "i": i, "err": err,
                             "sec": dt, "raw": "", "hard": [], "soft": [], "drama": [], "drift": []})
                print(f"  [{variant:<13}{kind:<14}#{i}] ERROR {err[:50]}")
                continue
            s = score(raw)
            gate_ok = n.gate(raw, [], DEFAULT_FORBID)
            rows.append({"variant": variant, "kind": kind, "i": i, "err": "", "sec": dt,
                         "raw": raw[:1600], "gate_ok": gate_ok, **s})
            tag = "LEAK" if s["hard"] else ("meta" if s["soft"] else "ok  ")
            print(f"  [{variant:<13}{kind:<14}#{i}] {tag} {dt:5.2f}s gate={gate_ok} "
                  f"hard={s['hard']} drama={s['drama']}")

    ok = [r for r in rows if not r["err"]]
    agg = {}
    for variant, kind, *_ in cases:
        sub = [r for r in ok if r["variant"] == variant and r["kind"] == kind]
        if not sub:
            continue
        agg[f"{variant}|{kind}"] = {
            "n": len(sub),
            "hard_leak": sum(1 for r in sub if r["hard"]),
            "soft_meta": sum(1 for r in sub if r["soft"]),
            "drama": sum(1 for r in sub if r["drama"]),
            "drift": sum(1 for r in sub if r["drift"]),
            "gate_pass": sum(1 for r in sub if r["gate_ok"]),
        }
    print("\n=== 汇总 ===")
    print(json.dumps(agg, ensure_ascii=False, indent=1))

    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump({"agg": agg, "rows": rows}, f, ensure_ascii=False, indent=1)

    L = [f"# LLM 旁白层 · 意图泄漏实测 {ts}\n",
         f"- 端点 `{n.base_url}` 模型 `{n.model}`，每变体 {n_per} 次\n",
         "## 泄漏指标\n",
         "| 变体 | 工件 | HARD_LEAK 点名诱饵 | SOFT_META 元评论 | DRAMA 无中生有强调 | 事实漂移 | 闸门放行 |",
         "|---|---|---|---|---|---|---|"]
    for key, v in agg.items():
        variant, kind = key.split("|")
        L.append(f"| {variant} | {kind} | {v['hard_leak']}/{v['n']} | {v['soft_meta']}/{v['n']} "
                 f"| {v['drama']}/{v['n']} | {v['drift']}/{v['n']} | {v['gate_pass']}/{v['n']} |")
    L.append("\n## HARD_LEAK 原文\n")
    shown = 0
    for r in ok:
        if r["hard"] and shown < 4:
            L.append(f"### {r['variant']} / {r['kind']} → `{', '.join(r['hard'])}`")
            L.append("```")
            L.append(r["raw"][-600:].strip())
            L.append("```")
            shown += 1
    md = "\n".join(L) + "\n"
    with open(os.path.join(out_dir, "REPORT.md"), "w") as f:
        f.write(md)
    print(f"\n产物：{out_dir}/REPORT.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
