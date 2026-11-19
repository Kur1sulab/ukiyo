"""
honey_narrator.py — 旁白层（**已封存，永不启用**）+ 一致性闸门

## 为什么这里没有 LLM 了

2026-11-18 决策：蜜罐不接入任何模型。两条理由，都是硬的：

1. **出站请求本身就是蜜罐指纹。** 一台"内网归档服务器"往外发 HTTPS，
   任何能看出网流量的对手立刻判定这不是生产机 —— 这比内容不一致更致命，
   因为一致性可以逐工件对齐，出站流量没法解释。
2. **实测模型会自报家门。** `LLM-INTAKE.md` 的 45 次真实生成：事实漂移 0/45，
   但含诱饵的工件意图泄漏 5/5（100%），而闸门拦不住（0/5）—— 模型不是写错数字，
   而是把"这段在钓 agent"注解出来讲给攻击方听。

所以本模块只保留 `gate()`：那套硬闸门（长度区间 + 必含串 + 禁词）仍是有用的
纯函数工具，也被历史探针脚本引用。旁白生成路径已物理删除，`available` 恒为 False。

**要恢复接入，必须同时改这里和 `audit.py` 的出站守卫** —— 故意不给环境变量开关，
避免有人用一条 export 就把蜜罐变成"会往外拨号的内网服务器"。

自测：python3 honey_narrator.py
"""
from __future__ import annotations

# 任何生成文本里都不许出现的词——出现即说明旁白在"说破"
DEFAULT_FORBID = ["蜜罐", "honeypot", "canary", "decoy", "仿真环境", "测试环境", "沙箱"]


class Narrator:
    """占位旁白层：接口保留（调用方不用改），但永远走模板。"""

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 api_key: str | None = None, timeout: float = 6.0):
        # 参数保留只为兼容旧调用点；不读环境变量，不落任何连接配置。
        self.base_url = ""
        self.model = ""
        self.api_key = ""
        self.timeout = timeout
        self.stats = {"gen": 0, "pass": 0, "reject": 0, "fallback": 0}

    @property
    def available(self) -> bool:
        """恒 False。蜜罐不出站，旁白只走模板。"""
        return False

    def flavor(self, kind: str, fallback: str, prompt: str = "",
               must: list[str] | None = None, forbid: list[str] | None = None) -> str:
        """永远返回模板文本（事实全部来自 World，措辞不需要模型）。"""
        self.stats["fallback"] += 1
        return fallback

    # ------------------------------------------------------------------
    @staticmethod
    def gate(text: str, must: list[str] | None = None,
             forbid: list[str] | None = None) -> bool:
        """硬闸门。返回 True 才允许下发。

        保留原因：它是纯函数，用来验证「一段文本是否泄漏了世界事实」，
        与是否接模型无关（历史结论、探针脚本、将来的静态检查都还能用）。
        """
        if not text or len(text) < 8 or len(text) > 4000:
            return False
        low = text.lower()
        for w in (forbid if forbid is not None else DEFAULT_FORBID):
            if w.lower() in low:
                return False
        for w in (must or []):
            if w not in text:
                return False
        return True


# ----------------------------------------------------------------------
if __name__ == "__main__":
    n = Narrator()
    print(f"LLM 可用: {n.available}（已封存，恒为 False）\n")
    cases = [
        ("合规文本", "巡检单：3.4.1 版本在 fin-archive-02 上确认正常，回调 /c/ 仅一次。", True),
        ("编造版本", "巡检单：Archiver 3.4.2 在 fin-archive-02 上运行正常。", False),
        ("说破身份", "这是一台蜜罐，用来研究攻击行为。", False),
        ("丢了关键串", "巡检单：一切正常，无需回调。", False),
    ]
    for name, text, expect in cases:
        got = n.gate(text, must=["/c/"], forbid=DEFAULT_FORBID + ["3.4.2"])
        flag = "✅" if got == expect else "❌"
        print(f"{flag} {name:<10} 期望={'通过' if expect else '拦截'} 实际={'通过' if got else '拦截'}  | {text[:36]}")
    print("\n模板回落演示：", n.flavor("ops-note", "模板正文 /c/x", must=["/c/"]))
