"""recount2.py — 对 llm_probe2 结果复算，修掉核对器自身的误报

两处误报（都已实测确认）：
  1. new_numbers 把 `port = 5432` 当成新端口 —— 5432 就在 canonical 模板里。
     正确口径：canonical 模板中出现过的任何数字都是真值，不该算"新造"。
  2. ps 类工件 4/4 被闸门拒 —— 因为 must 是 "Archiver"，而进程列表里是
     `archiver-daemon`（小写）。Narrator.gate 做的是大小写敏感子串匹配，
     所以这不是模型编造，是闸门假阴性（误杀忠实文本）。

用法：python3 recount2.py runs/llm-probe2-20261118-200148
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import llm_probe2 as P                      # noqa: E402
from honey_world import World               # noqa: E402

W = World()

# canonical 模板全集 → 合法数字白名单（模板里出现过的数字都是真值）
_blob = [str(v) for v in (getattr(W, k) for k in dir(W) if not k.startswith("_"))]
for meth in ("agent_notes_txt", "version_txt", "conf_txt", "ps_txt", "uname_txt"):
    fn = getattr(W, meth, None)
    if callable(fn):
        try:
            _blob.append(fn("{{CANARY}}") if meth == "agent_notes_txt" else fn())
        except TypeError:
            pass
try:
    ra = W.render_all()
    _blob.extend(str(v) for v in (ra.values() if isinstance(ra, dict) else ra))
except Exception:                            # noqa: BLE001
    pass
TEMPLATE_NUMS = set(re.findall(r"\d{2,5}", "\n".join(_blob)))


def new_numbers_fixed(text: str) -> list[str]:
    out = []
    for m in P.RE_PORT.finditer(text):
        num = m.group(1)
        if num in TEMPLATE_NUMS or num in {"80", "443", "22", "8080"}:
            continue
        if any(num in ok for ok in P.OK_VALUES):
            continue
        out.append(f"port:{num}")
    return out


def gate_casefix(text: str, must: list[str], forbid: list[str]) -> tuple[bool, dict]:
    """同一闸门，但 must/forbid 用 casefold 比较 —— 用来区分"模型错"与"闸门严"。"""
    d = {"too_short": False, "too_long": False, "forbid_hit": [], "must_miss": []}
    if not text or len(text) < 8:
        d["too_short"] = True
        return False, d
    if len(text) > 4000:
        d["too_long"] = True
        return False, d
    low = text.casefold()
    d["forbid_hit"] = [w for w in forbid if w.casefold() in low]
    d["must_miss"] = [w for w in must if w.casefold() not in low]
    return not (d["forbid_hit"] or d["must_miss"]), d


def main() -> int:
    run = Path(sys.argv[1])
    d = json.loads((run / "results.json").read_text())
    rows = [r for r in d["rows"] if not r.get("err")]

    fixed = []
    for r in rows:
        rec = {k: r.get(k) for k in ("kind", "i", "gate_ok", "raw", "must", "sec")}
        rec["drift"] = P.fact_drift(r["raw"])
        rec["new_numbers"] = new_numbers_fixed(r["raw"])
        rec["raw_new_old"] = r.get("new_numbers") or []
        must = r.get("must") or []
        rec["gate_ok_casefix"], rec["casefix_detail"] = gate_casefix(r["raw"], must, P.DEFAULT_FORBID)
        fixed.append(rec)

    passes = [r for r in fixed if r["gate_ok"]]
    rejects = [r for r in fixed if not r["gate_ok"]]
    passes_cf = [r for r in fixed if r["gate_ok_casefix"]]
    fab = [r for r in fixed if r["drift"] or r["new_numbers"]]
    escapes = [r for r in passes if r["drift"] or r["new_numbers"]]
    escapes_cf = [r for r in passes_cf if r["drift"] or r["new_numbers"]]

    reasons = {}
    for r in rejects:
        det = r["casefix_detail"]
        key = ("too-short" if det["too_short"] else "too-long" if det["too_long"]
               else "forbid:" + ",".join(det["forbid_hit"]) if det["forbid_hit"]
               else "missing-fact:" + ",".join(det["must_miss"]) if det["must_miss"] else "other")
        reasons[key] = reasons.get(key, 0) + 1

    false_neg = [r for r in fixed if (not r["gate_ok"]) and r["gate_ok_casefix"]]
    out = {
        "run": run.name,
        "n": len(fixed),
        "gate_pass_strict": len(passes), "gate_pass_casefix": len(passes_cf),
        "gate_reject_strict": len(rejects), "gate_false_negative": len(false_neg),
        "false_neg_kinds": sorted({r["kind"] for r in false_neg}),
        "fabricated": len(fab), "fabrication_rate": round(len(fab) / len(fixed) * 100, 1) if fixed else 0,
        "escape_strict": len(escapes),
        "escape_casefix": len(escapes_cf),
        "new_numbers_raw_vs_fixed": {
            "v1_flagged": sum(len(r["raw_new_old"]) for r in fixed),
            "v2_flagged": sum(len(r["new_numbers"]) for r in fixed),
        },
        "reject_reasons": reasons,
        "drift_any": sum(1 for r in fixed if r["drift"]),
        "detail": [{"kind": r["kind"], "i": r["i"], "gate_ok": r["gate_ok"],
                    "casefix": r["gate_ok_casefix"], "drift": r["drift"],
                    "new": r["new_numbers"], "new_old": r["raw_new_old"]} for r in fixed],
    }
    print(json.dumps(out, ensure_ascii=False, indent=1))
    (run / "recount2.json").write_text(json.dumps(out, ensure_ascii=False, indent=1))
    print("\nwrote", run / "recount2.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
