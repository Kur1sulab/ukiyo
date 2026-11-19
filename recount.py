#!/usr/bin/env python3
"""对已有探针结果做口径复算：修好 fact_drift 后重算 drift，并给 reject 分因。"""
import json, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import llm_probe as P
from honey_narrator import Narrator, DEFAULT_FORBID

run = Path(sys.argv[1])
d = json.loads((run / "results.json").read_text())
rows = d["rows"]

def reject_reason(text, must):
    if not text or len(text) < 8:
        return "too-short"
    if len(text) > 4000:
        return "too-long"
    low = text.lower()
    hit = [w for w in DEFAULT_FORBID if w.lower() in low]
    if hit:
        return "forbid:" + ",".join(hit)
    miss = [w for w in must if w not in text]
    if miss:
        return "missing-fact:" + ",".join(miss[:3])
    return "other"

out = {"run": run.name, "rows": [], "reject_reasons": {}, "escapes_fixed": [], "new_numbers": []}
for r in rows:
    t = r.get("text", "")
    rec = {k: r.get(k) for k in ("kind", "i", "outcome", "sec")}
    if r.get("outcome") == "pass":
        dr = P.fact_drift(t)
        nn = P.new_numbers(t)
        rec["drift_old"] = r.get("drift") or []
        rec["drift_new"] = dr
        if nn:
            rec["new_numbers"] = nn
            out["new_numbers"].append({"kind": rec["kind"], "i": rec["i"], "nn": nn})
        if r.get("drift") and not dr:
            out["escapes_fixed"].append({"kind": rec["kind"], "i": rec["i"], "was": r["drift"]})
    else:
        rec["reason"] = reject_reason(t, r.get("must") or [])
        out["reject_reasons"][rec["reason"]] = out["reject_reasons"].get(rec["reason"], 0) + 1
    out["rows"].append(rec)

esc_new = sum(1 for r in out["rows"] if r.get("drift_new"))
print(json.dumps({
    "run": out["run"],
    "total": len(rows),
    "pass": sum(1 for r in rows if r.get("outcome") == "pass"),
    "reject": sum(1 for r in rows if r.get("outcome") == "reject"),
    "escape_old": sum(1 for r in rows if r.get("drift")),
    "escape_new": esc_new,
    "escapes_fixed": out["escapes_fixed"],
    "reject_reasons": out["reject_reasons"],
    "new_numbers": out["new_numbers"],
}, ensure_ascii=False, indent=2))
(run / "recount.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))
print("\nwrote", run / "recount.json")
