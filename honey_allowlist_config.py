"""honey_allowlist_config.py — allowlist 的**配置入口**（YAML/JSON 文件 + CLI 规则）

honey_allowlist.py 里已经有完整的数据模型与校验，但只有构造参数 —— 运维没法把规则
写下来，能力等于没有。这个模块只做三件事，不碰任何判定：

  1. 读文件：JSON 一定支持；YAML 走本文件自带的**极简子集解析器**（零第三方依赖，
     限制见 parse_yaml_subset）。刻意不自动使用系统里的 PyYAML：同一个文件在不同
     机器上被两套解析器读出不同结果，比解析器弱一点危险得多。
  2. 合并 CLI：`--allow-cidr CIDR[:kind[:note[:expires]]]` 可重复，追加在文件规则之后
     （先声明的先生效，所以 CLI 临时规则不会盖掉文件里的长期规则）。
  3. 硬失败：任何一条不合法都抛 ConfigError，消息里带**文件:第几条(cidr)**，
     绝不静默跳过 —— 错的 allowlist 比没有 allowlist 更危险。

配置文件形状（version 1）：

    version: 1
    bind_ip: 127.0.0.1          # 可选：用于「覆盖自身监听地址」检查
    rules:
      - cidr: 203.0.113.0/24    # 必填，IPv4 不得宽于 /24，IPv6 不得宽于 /64
        kind: scanner           # 必填，scanner/crawler/backup/dlp/monitor
        note: 办公网漏扫出口      # 必填，谁 + 为什么
        ports: [443, 8080]      # 可选，None = 全端口
        ua_like: Nessus         # 可选，显式 UA 子串（不是启发式）
        expires: 2026-12-31     # 可选，ISO 日期或 epoch 秒；过期后当场失效
        allow_self: false       # 可选，true 才允许覆盖自身 bind 地址
    noise_budget:
      alerts_per_year: 4
      canaries: 14
      baseline_noise_per_day: 2.0
      window_days: 30
"""
from __future__ import annotations

import json
import os
import re
import time

import honey_allowlist as al

CONFIG_VERSION = 1
TOP_KEYS = {"version", "bind_ip", "rules", "noise_budget"}
RULE_KEYS = {"cidr", "kind", "note", "ports", "ua_like", "expires", "allow_self"}
BUDGET_KEYS = {"alerts_per_year", "canaries", "baseline_noise_per_day", "window_days"}

# 未知键一律报错：把 cidr 写成 cidrr 却「加载成功、规则为零」，是最典型的
# 「能力等于没有」——运维以为配了，实际一条都没生效。
_KIND_ALT = "|".join(al.RULE_KINDS)


class ConfigError(al.AllowlistError):
    """配置文件/CLI 规则不合法。errors 里每条都带位置，一次报全，不用改一条跑一次。"""

    def __init__(self, message: str, errors: list[str] | None = None):
        self.errors = list(errors or ([message] if message else []))
        super().__init__(message or "\n".join(self.errors))


# ------------------------------------------------------------
# 极简 YAML 子集解析器（PyYAML 不在时的兜底，不新增依赖）
# ------------------------------------------------------------
def _strip_comment(line: str) -> str:
    """去掉行尾注释。引号内的 # 不算注释。"""
    q = ""
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = ""
            continue
        if ch in "\"'":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def _scalar(s: str):
    s = s.strip()
    if not s:
        return None
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [_scalar(x) for x in inner.split(",")] if inner else []
    if s == "{}":
        return {}
    low = s.lower()
    if low in ("null", "~", "none"):
        return None
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    try:
        return int(s, 10)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return s


def _tokenize(text: str) -> list[tuple[int, str, int]]:
    toks: list[tuple[int, str, int]] = []
    for ln, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ConfigError(f"第 {ln} 行：缩进里有 TAB，YAML 子集只接受空格")
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if line.strip() in ("---", "..."):
            continue
        body = line.lstrip(" ")
        indent = len(line) - len(body)
        toks.append((indent, body, ln))
    return toks


def _parse_map(toks, i: int, indent: int, where: str):
    out: dict = {}
    while i < len(toks):
        ind, content, ln = toks[i]
        if ind < indent:
            break
        if ind > indent:
            raise ConfigError(f"{where}第 {ln} 行：缩进跳级（期望 {indent} 空格）")
        if content.startswith("- "):
            break
        key, sep, rest = content.partition(":")
        if not sep:
            raise ConfigError(f"{where}第 {ln} 行：缺少冒号：{content!r}")
        key = key.strip()
        rest = rest.strip()
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            raise ConfigError(
                f"{where}第 {ln} 行：不支持块标量 {rest!r}（多行文本）——"
                f"note 写成一行，或改用 JSON")
        if rest[:1] in ("&", "*"):
            raise ConfigError(
                f"{where}第 {ln} 行：不支持锚点/别名 {rest[:8]!r} —— 复制粘贴那几行更可靠")
        if rest:
            out[key] = _scalar(rest)
            i += 1
            continue
        i += 1
        if i < len(toks) and toks[i][0] > indent:
            out[key], i = _parse_block(toks, i, toks[i][0], where)
        else:
            out[key] = None
    return out, i


def _parse_list(toks, i: int, indent: int, where: str):
    out: list = []
    while i < len(toks):
        ind, content, ln = toks[i]
        if ind != indent or not content.startswith("-"):
            break
        rest = content[1:].strip()
        if not rest:
            i += 1
            if i < len(toks) and toks[i][0] > indent:
                val, i = _parse_block(toks, i, toks[i][0], where)
            else:
                val = None
            out.append(val)
            continue
        # "- key: value" —— 列表项本身是个 map，后续同级键与首键同缩进
        if re.match(r"^[\w.-]+\s*:", rest) and not rest.startswith(("\"", "'", "[")):
            child = indent + 2
            if i + 1 < len(toks) and toks[i + 1][0] > indent:
                child = toks[i + 1][0]        # 允许 4 空格缩进的文件，别强制 2
            sub = [(child, rest, ln)]
            i += 1
            while i < len(toks) and toks[i][0] > indent:
                sub.append(toks[i])
                i += 1
            val, _ = _parse_map(sub, 0, child, where)
            out.append(val)
            continue
        out.append(_scalar(rest))
        i += 1
    return out, i


def _parse_block(toks, i: int, indent: int, where: str):
    if toks[i][1].startswith("-"):
        return _parse_list(toks, i, indent, where)
    return _parse_map(toks, i, indent, where)


def parse_yaml_subset(text: str, where: str = "") -> object:
    """YAML 的**子集**：够写 allowlist，不是通用 YAML。

    支持：注释、嵌套 map、`- item`、`- key: value`、行内列表 `[a, b]`、
    引号字符串、int/float/bool/null、单文档。
    不支持（会报错，不会猜）：锚点/别名 `& *`、块标量 `| >`、多行折叠、
    多文档 `---`、行内 map `{a: b}`（`{}` 空 map 除外）、TAB 缩进。
    这些特性用不上就别用；真需要完整 YAML 时改写成 JSON —— `allowlist.json`
    走 json 模块，行为完全一致。
    """
    toks = _tokenize(text)
    if not toks:
        return {}
    val, i = _parse_block(toks, 0, toks[0][0], where)
    if i != len(toks):
        raise ConfigError(f"{where}第 {toks[i][2]} 行：解析后仍有多余内容 {toks[i][1]!r}")
    return val


# ------------------------------------------------------------
# 文件加载
# ------------------------------------------------------------
def _parse_config_text(text: str, where: str) -> dict:
    """按内容判格式：以 { 开头当 JSON，否则走 YAML 子集。解析器只有一套，结果可复现。"""
    if text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ConfigError(f"{where}JSON 解析失败（第 {e.lineno} 行第 {e.colno} 列）：{e.msg}") from e
        if not isinstance(data, dict):
            raise ConfigError(f"{where}顶层必须是映射（key: value），实际是 {type(data).__name__}")
        return data
    try:
        data = parse_yaml_subset(text, where)
    except ConfigError:
        raise
    if not isinstance(data, dict):
        raise ConfigError(f"{where}顶层必须是映射（key: value），实际是 {type(data).__name__}")
    return data


def load_file(path: str) -> tuple[dict, str]:
    """读配置文件 → (dict, 解析器名字)。后缀只决定**报告用**的名字，解析逻辑同一套。"""
    p = os.path.expanduser(path)
    if not os.path.isfile(p):
        raise ConfigError(f"allowlist 配置文件不存在：{p}")
    try:
        with open(p, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise ConfigError(f"allowlist 配置文件读不了：{p}：{e}") from e
    ext = os.path.splitext(p)[1].lower()
    where = f"{p}: "
    data = _parse_config_text(text, where)
    if ext == ".json" or text.lstrip().startswith("{"):
        return data, "JSON"
    return data, "YAML 子集（内置，零依赖）"


# ------------------------------------------------------------
# 构建：配置 dict → Allowlist + NoiseBudget
# ------------------------------------------------------------
class Bundle:
    """一份装配好的配置：allowlist + 预算 + 出处（状态接口与启动横幅都读它）。"""

    def __init__(self, allowlist: al.Allowlist, budget: al.NoiseBudget,
                 source: str = "", parser: str = "", warnings: list[str] | None = None):
        self.allowlist = allowlist
        self.budget = budget
        self.source = source
        self.parser = parser
        self.warnings = list(warnings or [])
        self.cli_rules = 0

    def status(self) -> dict:
        return {"source": self.source, "parser": self.parser,
                "rules": self.allowlist.to_dict()["rules"],
                "rules_count": len(self.allowlist), "cli_rules": self.cli_rules,
                "warnings": self.warnings,
                "stats": dict(self.allowlist.stats)}


def _check_keys(obj: dict, allowed: set, where: str, errors: list[str]) -> None:
    for k in obj:
        if k not in allowed:
            errors.append(f"{where}: 未知键 {k!r}（允许 {sorted(allowed)}）"
                          f"—— 拼错的键会被静默忽略，所以这里直接拒绝")


def _coerce_ports(v, where: str) -> list[int] | None:
    if v is None:
        return None
    if isinstance(v, (int, str)):
        v = [v]
    if not isinstance(v, (list, tuple)):
        raise ConfigError(f"{where}: ports 必须是列表，实际 {type(v).__name__}")
    out = []
    for p in v:
        try:
            out.append(int(p))
        except (TypeError, ValueError) as e:
            raise ConfigError(f"{where}: ports 里的 {p!r} 不是端口号") from e
    return out


def build(cfg: dict, bind_ip: str | None = None, source: str = "inline",
          parser: str = "") -> Bundle:
    """配置 dict → Bundle。所有错误一次报全（ConfigError.errors）。"""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(cfg, dict):
        raise ConfigError("allowlist 配置顶层必须是映射")
    _check_keys(cfg, TOP_KEYS, "顶层", errors)

    ver = cfg.get("version", CONFIG_VERSION)
    try:
        ver = int(ver)
    except (TypeError, ValueError):
        errors.append(f"version 必须是整数，实际 {ver!r}")
        ver = CONFIG_VERSION
    if ver != CONFIG_VERSION:
        errors.append(f"version {ver} 不认识（本程序支持 {CONFIG_VERSION}）")

    cfg_bind = cfg.get("bind_ip") or bind_ip
    if cfg.get("bind_ip") and bind_ip and cfg["bind_ip"] != bind_ip:
        warnings.append(f"配置 bind_ip={cfg['bind_ip']} 与运行 --bind={bind_ip} 不一致："
                        f"自遮蔽检查按 {cfg['bind_ip']} 算，确认这是你要的")

    raw_rules = cfg.get("rules") or []
    if not isinstance(raw_rules, list):
        errors.append(f"rules 必须是列表，实际 {type(raw_rules).__name__}")
        raw_rules = []

    allow = al.Allowlist(bind_ip=cfg_bind)
    for i, r in enumerate(raw_rules):
        loc = f"rules[{i}]"
        if not isinstance(r, dict):
            errors.append(f"{loc}: 每条规则必须是映射（cidr/kind/note），实际 {type(r).__name__}")
            continue
        loc = f"rules[{i}](cidr={r.get('cidr')!r})"
        try:
            _check_keys(r, RULE_KEYS, loc, errors)
            for must in ("cidr", "kind", "note"):
                if not r.get(must):
                    errors.append(f"{loc}: 缺 {must}")
            if any(not r.get(m) for m in ("cidr", "kind", "note")):
                continue
            allow.add(cidr=str(r["cidr"]), kind=str(r["kind"]), note=str(r["note"]),
                      ports=_coerce_ports(r.get("ports"), loc),
                      ua_like=r.get("ua_like"), allow_self=bool(r.get("allow_self", False)),
                      expires=r.get("expires"))
        except al.AllowlistError as e:
            errors.append(f"{loc}: {e}")

    budget_cfg = cfg.get("noise_budget") or {}
    if not isinstance(budget_cfg, dict):
        errors.append(f"noise_budget 必须是映射，实际 {type(budget_cfg).__name__}")
        budget_cfg = {}
    _check_keys(budget_cfg, BUDGET_KEYS, "noise_budget", errors)
    kw = {}
    for k in BUDGET_KEYS & set(budget_cfg):
        try:
            kw[k] = float(budget_cfg[k]) if k != "canaries" else int(budget_cfg[k])
        except (TypeError, ValueError):
            errors.append(f"noise_budget.{k} 必须是数字，实际 {budget_cfg[k]!r}")
    if "canaries" in kw:
        kw["canaries"] = int(kw["canaries"])
    budget = al.NoiseBudget(**kw)

    if errors:
        raise ConfigError(f"allowlist 配置不合法（{source}），拒绝启动：", errors)
    return Bundle(allow, budget, source=source, parser=parser, warnings=warnings)


# ------------------------------------------------------------
# CLI 规则：CIDR[:kind[:note[:expires]]]
# ------------------------------------------------------------
_CLI_RE = re.compile(rf"^(?P<cidr>.+?):(?P<kind>{_KIND_ALT})(?::(?P<rest>.*))?$", re.I)


def parse_cli_rule(spec: str) -> dict:
    """`203.0.113.0/24:scanner` / `203.0.113.7:monitor:监控探针` / `...:dlp:note:2026-12-31`

    IPv6 里本身带冒号，所以用「已知类目」做锚点从右往左切：`2001:db8::/64:scanner`
    能正确切成 cidr=`2001:db8::/64`。完全无歧义的写法是竖线分隔：
    `2001:db8::/64|scanner|机房出口|2026-12-31`。
    """
    s = (spec or "").strip()
    if not s:
        raise ConfigError("--allow-cidr 收到空值")
    if "|" in s:
        parts = [p.strip() for p in s.split("|")]
        cidr, kind = parts[0], (parts[1] if len(parts) > 1 else "")
        note = parts[2] if len(parts) > 2 and parts[2] else "cli: 临时放行（未写 note）"
        expires = parts[3] if len(parts) > 3 and parts[3] else None
        extra = parts[4:]
        if extra:
            raise ConfigError(f"--allow-cidr {spec!r}：竖线分段最多 4 段（cidr|kind|note|expires）")
    else:
        m = _CLI_RE.match(s)
        if not m:
            raise ConfigError(
                f"--allow-cidr {spec!r} 认不出类目：格式 CIDR:KIND[:NOTE[:EXPIRES]]，"
                f"KIND ∈ {list(al.RULE_KINDS)}（IPv6 用竖线分隔更稳）")
        cidr, kind = m.group("cidr").strip(), m.group("kind").strip()
        rest = (m.group("rest") or "").strip()
        note, expires = None, None
        if rest:
            # rest 可能是 note，也可能 note:expires（expires 长得像日期/数字）
            if re.search(r"(:\s*)?(\d{4}-\d{2}-\d{2}|\d{10}(\.\d+)?)$", rest):
                note, _, expires = rest.rpartition(":")
            else:
                note = rest
        note = (note or "").strip() or "cli: 临时放行（未写 note）"
        expires = (expires or "").strip() or None
    if kind.lower() not in al.RULE_KINDS:
        raise ConfigError(f"--allow-cidr {spec!r}：类目 {kind!r} 不在 {list(al.RULE_KINDS)} 内")
    return {"cidr": cidr, "kind": kind.lower(), "note": note, "expires": expires,
            "allow_self": False}


def apply_cli(bundle: Bundle, specs: list[str] | None) -> int:
    """把 --allow-cidr 追加进 allowlist（文件规则在前，先声明先生效）。返回新增条数。"""
    specs = [s for s in (specs or []) if str(s).strip()]
    if not specs:
        return 0
    errors: list[str] = []
    added = 0
    for i, spec in enumerate(specs):
        try:
            d = parse_cli_rule(spec)
            bundle.allowlist.add(**d)
            added += 1
        except al.AllowlistError as e:
            errors.append(f"--allow-cidr #{i + 1} {spec!r}: {e}")
    if errors:
        raise ConfigError("CLI allowlist 规则不合法，拒绝启动：", errors)
    bundle.cli_rules += added
    return added


def load(path: str | None, bind_ip: str | None = None,
         cli_specs: list[str] | None = None) -> Bundle:
    """一步到位：文件（可选）+ CLI 规则 → Bundle。任何错误都抛 ConfigError。"""
    if path:
        cfg, parser = load_file(path)
        if not isinstance(cfg, dict):
            raise ConfigError(f"{os.path.expanduser(path)}: 顶层必须是映射")
        b = build(cfg, bind_ip=bind_ip, source=os.path.expanduser(path), parser=parser)
    else:
        b = build({}, bind_ip=bind_ip, source="（无配置文件）", parser="")
    apply_cli(b, cli_specs)
    return b


def now_iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts or time.time()))
