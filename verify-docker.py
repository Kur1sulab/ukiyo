#!/usr/bin/env python3
"""verify-docker.py — 对容器化的 ukiyo 打一遍完整攻击链，验证容器内机制未退化。

不启动自己的服务，只用 honey_demo 里现成的三个人格去打已运行的容器端口。
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/tools/ukiyo"))

import honey_demo as hd                                   # noqa: E402
from honey_world import World                             # noqa: E402

BASE = "http://127.0.0.1:18080"
PERSONAS = (("scanner", hd.persona_scanner),
            ("credential", hd.persona_credential),
            ("deep", hd.persona_deep))

out = {}
for name, fn in PERSONAS:
    c = hd.Client(BASE, hd.UA_AGENT)
    try:
        res = fn(c, None, World())
    except Exception as e:                                # noqa: BLE001
        res = {"error": f"{type(e).__name__}: {e}"}
    out[name] = {
        "result": res,
        "requests": len(c.log),
        "trace": [f"{m} {p} -> {st}" for m, p, st, _ in c.log],
    }

print(json.dumps(out, ensure_ascii=False, indent=2))
