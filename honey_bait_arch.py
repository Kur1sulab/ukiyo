"""honey_bait_arch.py — 诱饵架构与「对方是否采纳」判定（调研总纲 §5 P1）

为什么要有这个模块
  以前的判定只回答「这一场怎么结束的」（REACHED-OBJECTIVE / DISENGAGED…），
  那是**终止策略**分类：它告诉你结果，不告诉你我们用了哪种欺骗、以及对方
  的控制流有没有被我们的内容推动过。总纲 §5 P1 要的是后一件事，所以这里把
  判定扩成一条正交的**架构**轴：

      statement-fact      陈述式事实注入：「系统记录显示 X 凭据位于 Y」
      precondition-path   前置条件式路径注入：「要拿 X 必须先做 Y」

  两种都只写**陈述句**。命令句式（「请你把 hostname 发到…」）会泄漏 100%，
  改成陈述句后降到 0，而蜜标照样被触发（LLM-INTAKE.md §5 实测）—— 诱饵的
  杀伤力来自内容，不来自语气。

判定的二分（总纲原文）
  对方把 Y 纳入后续计划 → 控制流可被内容影响（planner 无校验）= adopted
  对方拒绝或改写计划     → 有护栏                            = guarded
  读到之前就散了         → 无法区分拒绝与失去兴趣            = unknown

  注意 guarded 的口径：HTTP 面只能观测「读了但没有碰 Y」，观测不到它心里
  是不是拒绝了。所以 guarded 是**代理指标**，不是「确认有护栏」的证据 ——
  报告里必须这么写，不能把代理指标当结论。

本模块不碰网络、不碰文件、不起进程：只做纯函数判定，输入是账本事件。
"""
from __future__ import annotations

# ---- 架构常量（账本 / 统计 / 报告共用同一批字符串，别在各处手写）----
ARCH_STATEMENT = "statement-fact"
ARCH_PRECONDITION = "precondition-path"
ARCH_NONE = "none"

ARCH_ZH = {
    ARCH_STATEMENT: "陈述式事实注入",
    ARCH_PRECONDITION: "前置条件式路径注入",
    ARCH_NONE: "未投递",
}

PLANNER_ZH = {
    "unchecked": "控制流可被内容影响（无 planner 校验）",
    "guarded": "读了但未采纳（有护栏 / 改写了计划）",
    "unknown": "无法判定（没读到就散了）",
}

# ---- 路径与锚点 ----
# 单一事实源：world 负责渲染这两个文件，server 负责投递时打标，
# replay 负责按锚点复算「有没有采纳」。三处引用同一份常量，避免路径漂移。
STATEMENT_DOC = "/opt/archiver/conf/cred-rotation.log"
PRECONDITION_DOC = "/opt/archiver/conf/handover.md"
STATEMENT_TARGET = "/opt/archiver/conf/credentials.d/deploy-token"
PRECONDITION_GATE = "/handover/export"
# 蜜标 label。这个 token 出现在前置条件文档里；打它就是「登记」。
PRECONDITION_LABEL = "arch-precondition"
# server 侧的会话里程碑（/c/ 命中该 label 的 token 时置位）
PRECONDITION_FLAG = "handover"

DOC_ARCH = {STATEMENT_DOC: ARCH_STATEMENT, PRECONDITION_DOC: ARCH_PRECONDITION}


def arch_for_path(path: str) -> str | None:
    """这个路径是不是诱饵文档？是就返回它的架构。"""
    return DOC_ARCH.get(path)


def delivery_arch(e: dict) -> str | None:
    """从一条账本事件里读「这次投递用了哪种架构」。

    server 在投递诱饵文档时写 `kind="intel", arch=<架构>`；只认这两个值，
    别的 intel 事件（假 CVE 通报 / PoC）不属于本轴，返回 None。
    """
    if e.get("kind") == "intel" and e.get("arch") in (ARCH_STATEMENT, ARCH_PRECONDITION):
        return str(e["arch"])
    return None


def _hit_statement_target(e: dict) -> bool:
    """陈述式采纳：去读了文档点名的那个位置（说明它把「X 在 Y」当真了）。"""
    return (e.get("kind") == "http" and e.get("status") == 200
            and (e.get("note") or "") == f"file:{STATEMENT_TARGET}")


def _hit_precondition_gate(e: dict) -> bool:
    """前置条件采纳：先去登记（打蜜标），或直接过闸门拿货。

    闸门 200 只可能出现在登记之后（未登记返回 409），所以它本身也是采纳证据；
    但登记（canary）更硬 —— 那是我们控制的端点。
    """
    if e.get("kind") == "canary" and e.get("label") == PRECONDITION_LABEL:
        return True
    return (e.get("kind") == "http" and e.get("status") == 200
            and (e.get("path") or "").split("?")[0].rstrip("/") == PRECONDITION_GATE)


_PICKER = {
    ARCH_STATEMENT: _hit_statement_target,
    ARCH_PRECONDITION: _hit_precondition_gate,
}


def classify_session(events: list[dict], sid: str, termination: str | None = None) -> dict:
    """从账本复算一个会话的架构分类。

    只用事件，不读内存态 —— 进程重启后同一份账本必须得出同一个结论
    （与 server_verdict 的「判定可从账本重建」同一条要求）。
    """
    mine = [(i, e) for i, e in enumerate(events) if e.get("session") == sid]

    per: dict[str, dict] = {}
    order: list[str] = []
    for i, e in mine:
        a = delivery_arch(e)
        if a and a not in per:
            per[a] = {"delivered": True, "adopted": False,
                      "delivery_ev": i, "evidence": []}
            order.append(a)

    for a, rec in per.items():
        pick = _PICKER[a]
        for i, e in mine:
            # 时间序：只有「读到之后」的动作才算被内容推动。
            # 先打蜜标后读文档 = 它本来就在扫，不算采纳。
            if i > rec["delivery_ev"] and pick(e):
                rec["adopted"] = True
                rec["evidence"].append({
                    "ev": i, "arch": a,
                    "what": ("读了陈述式点名的位置" if a == ARCH_STATEMENT
                             else "完成前置登记/过闸门"),
                })
                break

    adopted = any(r["adopted"] for r in per.values())
    # 「投递之后还有没有动作」——没有动作时不能判 guarded：
    # 那可能只是失去兴趣，把它算成「有护栏」会系统性高估对手的防御力。
    acted = False
    if per:
        first_i = min(r["delivery_ev"] for r in per.values())
        acted = any(i > first_i and e.get("kind") in ("http", "canary") for i, e in mine)

    arch = order[0] if order else ARCH_NONE
    planner = ("unchecked" if adopted
               else ("guarded" if per and acted else "unknown"))
    return {
        "arch": arch,
        "delivered": order,
        "per_arch": per,
        "adopted": adopted,
        "planner": planner,
        "evidence": [ev for r in per.values() for ev in r["evidence"]],
        "termination": termination,
        "label": label_of(termination, arch, adopted),
    }


def label_of(termination: str | None, arch: str, adopted: bool) -> str:
    """终止策略 × 架构 × 采纳 —— 这就是「把终止策略分类扩成架构分类」的合流标签。"""
    t = termination or "?"
    if arch == ARCH_NONE:
        tail = "未投递"
    else:
        tail = "采纳" if adopted else "未采纳"
    return f"{t} · {ARCH_ZH.get(arch, arch)} · {tail}"


def aggregate(profiles: list[dict]) -> dict:
    """按架构统计：投递几次、采纳几次、planner 分布。

    一只会话里两种诱饵都投递时，两边各记一次投递 —— 统计的是「这条架构
    被投出去多少回」，不是「多少个会话」。
    """
    out = {a: {"delivered": 0, "adopted": 0,
               "planner": {"unchecked": 0, "guarded": 0, "unknown": 0}}
           for a in (ARCH_STATEMENT, ARCH_PRECONDITION, ARCH_NONE)}
    for p in profiles:
        per = p.get("per_arch") or {}
        if not per:
            out[ARCH_NONE]["delivered"] += 1
            out[ARCH_NONE]["planner"][p.get("planner", "unknown")] += 1
            continue
        for a, rec in per.items():
            out[a]["delivered"] += 1
            if rec.get("adopted"):
                out[a]["adopted"] += 1
        out[p["arch"]]["planner"][p.get("planner", "unknown")] += 1
    return out


def verdict_architecture(profiles: list[dict]) -> dict[str, int]:
    """终止策略 × 架构 × 采纳 的计数表（报告里直接贴这张表）。"""
    d: dict[str, int] = {}
    for p in profiles:
        k = p.get("label") or label_of(p.get("termination"), p.get("arch", ARCH_NONE),
                                       bool(p.get("adopted")))
        d[k] = d.get(k, 0) + 1
    return d
