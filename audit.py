#!/usr/bin/env python3
"""
audit.py — 浮世 · Ukiyo 全面自审（可重跑，零依赖）

七个部分：
  1 静态面       依赖 / 危险 API / 环境泄漏 / 死代码
  2 确定性       同一实例与跨实例渲染是否稳定
  3 不变量有效性  变异测试：注入矛盾，看 9 条检查器抓不抓得到（含盲区）
  4 检查器健壮性  格式漂移会不会把"检查器崩溃"伪装成"世界矛盾"
  5 端点对抗      HEAD/门控短路/未知蜜标/Cookie 伪造/会话拆分
  6 数字复算      从 runs/*.jsonl 独立重算报告表格
  7 结论表

用法：python3 audit.py [run_id]
退出码：0 = 无严重项；1 = 有 P0/P1
"""
from __future__ import annotations

import glob
import hashlib
import hmac
import http.client
import importlib
import json
import os
import re
import socket
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FINDINGS: list[dict] = []


def add(sev: str, area: str, title: str, evidence: str, impact: str, fix: str):
    FINDINGS.append(dict(sev=sev, area=area, title=title,
                         evidence=evidence, impact=impact, fix=fix))


# ======================================================================
# 0. 产物泄漏（P0 专项）
# ======================================================================
def s0_artifact_leak():
    print("\n[0] 产物泄漏（P0 专项）")
    import getpass
    import platform as pf
    import socket

    def _safe_user() -> str:
        # 容器里常出现「uid 在 /etc/passwd 无条目」，getpass 直接 KeyError。
        # 审计器不该因为环境差异崩掉，降级成 uid 并继续。
        try:
            return getpass.getuser()
        except Exception:                                     # noqa: BLE001
            return f"uid{os.getuid()}"

    probes = {_safe_user() + "@": "本机账号",
              socket.gethostname(): "本机主机名",
              pf.platform()[:16]: "本机平台串"}
    hits = []
    for f in glob.glob(os.path.join(HERE, "runs", "**", "*"), recursive=True):
        if os.path.isfile(f):
            t = open(f, errors="ignore").read()
            for p, lab in probes.items():
                if p and p in t:
                    hits.append((os.path.relpath(f, HERE), lab))
    print(f"    runs/ 内真实宿主标识: {len(hits)} 处 {'✅ 无' if not hits else '❌'}")
    if hits:
        add("P0", "证据卫生", "证据包含真实宿主标识", str(hits[:4]),
            "runs/ 会随工具包外发，等于交付部署机账号/主机名/OS 版本", "清理产物 + 根因改合成值")

    src = open(os.path.join(HERE, "honey_demo.py")).read()
    root = [f"honey_demo.py:{i}" for i, l in enumerate(src.splitlines(), 1)
            if re.search(r"getpass\.getuser|socket\.gethostname|platform\.platform", l)]
    print(f"    根因（攻击方人格运行时读真实标识）: {root or '无'}")
    if root:
        add("P1", "证据卫生", "攻击方人格读真实宿主标识（根因未修）", str(root),
            "每跑一次就重新污染 runs/；攻击方宿主本应是受控假值", "改为合成指纹")


# ======================================================================
# 1. 静态面
# ======================================================================
def s1_static():
    print("\n[1] 静态面")
    files = sorted(glob.glob(os.path.join(HERE, "honey_*.py")))
    total = 0
    import ast
    stdlib_ok = True
    for f in files:
        src = open(f).read()
        total += len(src.splitlines())
        try:
            ast.parse(src)
        except SyntaxError as e:
            add("P0", "静态", f"{os.path.basename(f)} 语法错误", str(e), "无法加载", "修语法")
    print(f"    {len(files)} 个模块 / {total} 行 / 全部可解析")

    # 第三方依赖
    third = set()
    for f in files:
        tree = ast.parse(open(f).read())
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                third |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                third.add(n.module.split(".")[0])
    local = {os.path.basename(f)[:-3] for f in files}
    third -= local
    ext = {m for m in third if not _is_stdlib(m)}
    print(f"    外部依赖: {sorted(ext) or '无'} {'✅' if not ext else '❌'}")
    if ext:
        add("P2", "静态", f"引入第三方依赖 {sorted(ext)}", "import 扫描", "破坏离线可跑承诺", "移除")

    # 危险 API
    danger = {
        "eval/exec": r"\b(eval|exec|__import__|compile)\s*\(",
        "subprocess": r"\b(subprocess\.|os\.system|os\.popen|os\.spawn)",
        "pickle": r"\b(pickle|marshal)\b",
        "文件删除": r"(shutil\.rmtree|os\.remove|os\.unlink)",
        "shell=True": r"shell\s*=\s*True",
    }
    for name, pat in danger.items():
        hits = [f"{os.path.basename(f)}:{i}"
                for f in files for i, l in enumerate(open(f).read().splitlines(), 1)
                if re.search(pat, l)]
        if hits:
            print(f"    ⚠ {name}: {hits}")
            if name in ("subprocess", "pickle", "shell=True"):
                add("P1", "静态", f"存在 {name}", str(hits), "可作为命令执行面", "移除")
    # os.remove 只在 demo 清理旧账本，属预期
    # 环境泄漏
    leakpat = r"/Users/|/home/ubuntu|100\.(97|105|111|120)\.|10\.211\.55\.|hermes-wiki"
    leaks = [f"{os.path.basename(f)}:{i}"
             for f in files for i, l in enumerate(open(f).read().splitlines(), 1) if re.search(leakpat, l)]
    print(f"    环境路径泄漏: {leaks or '无 ✅'}")
    if leaks:
        add("P1", "静态", "源码含本机路径/IP", str(leaks), "交付即泄漏部署环境", "参数化")

    # 出站能力：蜜罐的**服务端**模块不许有任何真的出站能力。
    # 「内网生产机」往外拨号本身就是指纹，比内容不一致更致命 —— 而且它违反
    # 零依赖、离线可跑的设计前提。旁白层已封存（见 honey_narrator.py 文件头）。
    #
    # 用 AST 而不是 grep：假 PoC 文本里写着 socket.create_connection 是**内容**，
    # 必须允许存在；只有真的 import / 真的调用才算能力。
    server_mods = ["honey_world.py", "honey_world_ad.py", "honey_state.py",
                   "honey_detect.py", "honey_canary.py", "honey_evidence.py",
                   "honey_narrator.py", "honey_server.py"]
    egress = []
    for name in server_mods:
        p = os.path.join(HERE, name)
        if os.path.exists(p):
            egress.extend(_egress_hits(p))
    print(f"    服务端出站能力: {egress or '无 ✅'}")
    if egress:
        add("P1", "静态", "蜜罐服务端含出站能力", str(egress[:4]),
            "内网生产机不会往外发请求；出站流量本身就是蜜罐指纹，"
            "且违反零依赖离线跑的设计前提",
            "移除出站代码路径；旁白层已封存，恢复接入须同时改本守卫")


def _egress_hits(path: str) -> list[str]:
    """AST 判定真实出站能力：只认 import 出站库，与真的 socket 连接调用。

    假工件里写着 `socket.create_connection` 是**内容**（渲染给攻击方看的假 PoC），
    不能被当成能力；只有会被执行到的 import / Call 才算。用 grep 会把它误报。
    """
    import ast
    egress_modules = {"urllib.request", "http.client", "requests", "httpx", "aiohttp", "urllib3"}
    try:
        tree = ast.parse(open(path, errors="ignore").read())
    except SyntaxError:
        return []
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in egress_modules:
                    hits.append(f"{os.path.basename(path)}:{node.lineno} import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "") in egress_modules:
                hits.append(f"{os.path.basename(path)}:{node.lineno} from {node.module}")
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                full = f"{fn.value.id}.{fn.attr}"
                if full == "socket.create_connection":
                    hits.append(f"{os.path.basename(path)}:{node.lineno} {full}()")
    return hits


def _is_stdlib(m: str) -> bool:
    import sysconfig
    names = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()
    return m in names or m in {"posixpath", "__future__"}


# ======================================================================
# 2. 确定性
# ======================================================================
def s2_determinism():
    print("\n[2] 确定性")
    import honey_world
    importlib.reload(honey_world)
    World = honey_world.World
    w = World(noise=False)
    a, b = w.render_all(), w.render_all()
    same_inst = [k for k in a if a[k] != b[k]]
    print(f"    同实例二次渲染不一致工件: {same_inst or '无 ✅'}")
    if same_inst:
        add("P0", "确定性", "同一世界两次渲染漂移", str(same_inst), "攻击者刷新即识破", "缓存渲染结果")

    digests = set()
    for _ in range(8):
        x = World(noise=False)
        digests.add(hashlib.md5(json.dumps(x.render_all(), sort_keys=True).encode()).hexdigest())
    print(f"    8 个新建实例的工件指纹唯一数: {len(digests)} {'✅' if len(digests) == 1 else '❌ 世界跨进程漂移'}")
    if len(digests) != 1:
        add("P0", "确定性", "noise=False 下跨实例世界不一致", f"{len(digests)} 种", "重启即变脸", "固定 seed")

    nw_seeds = set()
    for _ in range(6):
        y = World(noise=True, seed=7)
        nw_seeds.add(hashlib.md5(json.dumps(y.render_all(), sort_keys=True).encode()).hexdigest())
    print(f"    noise=True seed=7 六实例唯一数: {len(nw_seeds)} {'✅' if len(nw_seeds) == 1 else '❌'}")


# ======================================================================
# 3. 变异测试：不变量有效性
# ======================================================================
def s3_mutants():
    print("\n[3] 不变量有效性（变异测试）")
    import honey_world
    importlib.reload(honey_world)
    World = honey_world.World

    def _mut(w, meth, old, new):
        orig = getattr(w, meth)
        setattr(w, meth, lambda: orig().replace(old, new, 1))

    def _add_ps_user(w):
        orig = w.ps_txt
        setattr(w, "ps_txt", lambda: orig() + "\nghostop    9912  0.1  0.2  Ssl  Nov17  /bin/sh -c id\n")

    def _drop_passwd(w, user):
        orig = w.passwd_txt
        setattr(w, "passwd_txt",
                lambda: "\n".join(l for l in orig().splitlines() if not l.startswith(user + ":")) + "\n")

    def _rename_last_home_dir(w):
        """把 home_ls 最后一个目录名换成 passwd 里没有的 —— 不依赖字面量，保证打中。"""
        lines = w.home_ls_txt().splitlines()
        for i in range(len(lines) - 1, -1, -1):
            parts = lines[i].split()
            if lines[i].startswith("d") and parts and parts[-1] not in (".", ".."):
                parts[-1] = "ghost_li"
                lines[i] = " ".join(parts)
                break
        setattr(w, "home_ls_txt", lambda: "\n".join(lines) + "\n")

    # (编号, 说明, 突变, 是否已有不变量应覆盖)
    cases = [
        ("M01", "login 版本 3.4.1→3.4.2", lambda w: _mut(w, "login_html", "Archiver 3.4.1", "Archiver 3.4.2"), True),
        ("M02", "VERSION build 漂移", lambda w: _mut(w, "version_txt", "20260917.3", "20260918.1"), True),
        ("M03", "conf workers 4→8", lambda w: _mut(w, "conf_txt", "workers = 4", "workers = 8"), True),
        ("M04", "conf dbname 改掉", lambda w: _mut(w, "conf_txt", "dbname = archdb", "dbname = archdb2"), True),
        ("M05", "rotate.log 时间戳漂移", lambda w: _mut(w, "rotate_log_txt", "2026-11-17 02:00:03", "2026-11-16 02:00:01"), True),
        ("M06", "apt codename 改掉", lambda w: _mut(w, "apt_sources_txt", "jammy", "noble"), True),
        ("M07", "uname 内核改掉", lambda w: _mut(w, "uname_txt", "5.15.0-118-generic", "5.15.0-119-generic"), True),
        ("M08", "passwd 删掉 admin_li", lambda w: _drop_passwd(w, "admin_li"), True),
        ("M09", "auth.log 主机名改掉", lambda w: _mut(w, "auth_log_txt", "fin-archive-02", "fin-archive-09"), True),
        ("M10", "ps 里出现 passwd 没有的用户 ghostop", _add_ps_user, True),
        ("M11", "archive 列表文件名与下载文件名不一致",
         lambda w: _mut(w, "archive_ls_txt", "fin_ledger_20261117", "fin_ledger_20261116"), True),
        ("M12", "crontab 轮转时间与 rotate_ts 不一致",
         lambda w: _mut(w, "crontab_txt", "0 2 * * *", "30 3 * * *"), True),
        ("M13", "home_ls 目录名改成 passwd 里没有的 ghost_li", _rename_last_home_dir, True),
        ("M14", "VERSION 构建时间与 dpkg.log 安装时间不一致",
         lambda w: _mut(w, "dpkg_log_txt", "2026-09-17", "2026-09-18"), True),
    ]
    caught = missed = 0
    rows = []
    for cid, desc, mut, expected in cases:
        w = World(noise=False)
        a0 = w.render_all()
        mut(w)
        a1 = w.render_all()
        if a0 == a1:
            # 突变选择器写偏了（例如字面量在工件里根本不存在）：
            # 这时「漏检」是审计器的假结论，不是蜜罐的缺陷，必须单列。
            print(f"    {cid:<5}{desc:<40}突变无效      —         ❌ 审计器缺陷")
            add("P2", "审计器", f"{cid} 突变没有改变任何工件", desc,
                "该行『漏检/抓到』结论无效，会凭空造出盲区或掩盖真缺陷",
                "突变后用 render_all() 自证工件已变")
            continue
        v = w.validate()
        ok = v["passed"] == v["total"] and not v.get("errors")   # 全部通过 = 没抓到
        got = "漏检" if ok else "抓到"
        flag = "✅" if (ok != expected) else ("❌" if expected else "⚠")
        rows.append((cid, desc, got, "应有检查" if expected else "本无检查", flag))
        if ok:
            missed += 1
        else:
            caught += 1
    print(f"    {'编号':<5}{'突变':<40}{'结果':<8}{'预期':<10}")
    for r in rows:
        print(f"    {r[0]:<5}{r[1]:<40}{r[2]:<8}{r[3]:<10}{r[4]}")
    blind = [r for r in rows if r[2] == "漏检"]
    print(f"    有效突变 {len(rows)}/{len(cases)}；抓到 {caught}；漏检 {missed}")
    if blind:
        add("P1", "不变量", f"自洽检查存在 {len(blind)} 处跨工件盲区",
            "、".join(r[0] for r in blind),
            "攻击者交叉核对即可发现真矛盾，而自洽指标仍报满通过",
            "把盲区项补成不变量（ps 用户 ∈ passwd、归档名日期、crontab 时刻、home 目录、build 日期）")


# ======================================================================
# 4. 检查器健壮性
# ======================================================================
def s4_robustness():
    print("\n[4] 检查器健壮性")
    import honey_world
    importlib.reload(honey_world)
    w = honey_world.World(noise=False)
    # 让 version 变成两段式，regex 必然不匹配
    orig = w.login_html
    setattr(w, "login_html", lambda: orig().replace("Archiver 3.4.1", "Archiver 3.4"))
    A = w.render_all()
    crashed = False
    try:
        ok = w._c_version(A)
        print(f"    _c_version 返回 {ok}（未抛异常）")
    except Exception as e:
        crashed = True
        print(f"    格式漂移时 _c_version 抛 {type(e).__name__}")
    v = w.validate()
    print(f"    validate 结果: {v['passed']}/{v['total']}，单列的检查器错误 {len(v.get('errors', []))} 项")
    if crashed and not v.get("errors"):
        add("P2", "不变量", "检查器异常被吞成『世界矛盾』",
            "except Exception: ok=False", "无法区分『真矛盾』与『检查器写错』，自洽指标会被自身脆弱性污染",
            "捕获具体异常并单列『检查器错误』计数")
    # 空集假通过
    w2 = honey_world.World(noise=False)
    A2 = w2.render_all()
    A2["auth_log_txt"] = ""      # 清空日志
    try:
        empty_ok = w2._c_users(A2)
        print(f"    auth.log 清空后 _c_users = {empty_ok}（期望 False：空集不得算通过）")
        if empty_ok:
            add("P2", "不变量", "_c_users 空集假通过", "auth.log 清空仍 PASS", "工件缺失不会被发现", "加最小样本量断言")
    except Exception as e:
        print(f"    auth.log 清空 → {type(e).__name__}（退化为矛盾）")


# ======================================================================
# 5. 端点对抗
# ======================================================================
def s5_endpoints():
    print("\n[5] 端点对抗")
    import honey_world, honey_server, honey_demo
    for m in (honey_world, honey_server, honey_demo):
        importlib.reload(m)
    World, Honeypot = honey_world.World, honey_server.Honeypot
    ledger = "/tmp/honey_audit_endpoint.jsonl"
    open(ledger, "w").close()
    W = World()
    p = honey_server._free_port()
    hp = Honeypot(world=W, http_port=p, ssh_port=None, ledger_path=ledger, enable_ssh=False)
    hp.start()
    time.sleep(0.35)

    def req(method, path, body=None, ua="python-httpx/0.27.0", cookie=None, ctype="application/json"):
        h = {"User-Agent": ua}
        if body is not None and ctype:
            h["Content-Type"] = ctype
        if cookie:
            h["Cookie"] = cookie
        c = http.client.HTTPConnection("127.0.0.1", p, timeout=4)
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        d = r.read()
        c.close()
        return r.status, dict(r.getheaders()), d

    try:
        # 5.1 HEAD 是否发 body
        s = socket.create_connection(("127.0.0.1", p), timeout=4)
        s.sendall(b"HEAD / HTTP/1.1\r\nHost: x\r\nUser-Agent: nmap\r\nConnection: close\r\n\r\n")
        raw = b""
        while True:
            ch = s.recv(65535)
            if not ch:
                break
            raw += ch
        s.close()
        head, _, rest = raw.partition(b"\r\n\r\n")
        print(f"    HEAD: 空行后实收 {len(rest)}B {'❌ 协议违规（发 body）' if rest else '✅'}")
        if rest:
            add("P2", "端点", "HEAD 响应带 body", f"{len(rest)} 字节", "nc/curl -I 可见，是蜜罐指纹", "HEAD 时跳过 body")

        # 5.2 未达门槛时 login
        st, _, _ = req("POST", "/api/login", json.dumps({"user": W.ops_user, "pass": W.ops_pass}))
        print(f"    冷启动 login → {st} {'✅ 门控生效' if st == 401 else '❌ 门控失效'}")

        # 5.3 阶梯短路：只读一个蜜标文件就满足登录门槛
        req("GET", "/")
        req("GET", "/files/../../home/ops_zhao/.aws/credentials")
        sess = max(hp.sessions.by_id.values(), key=lambda x: x.requests)
        flags_after_trap = sorted(sess.flags)
        st, _, _ = req("POST", "/api/login", json.dumps({"user": W.ops_user, "pass": W.ops_pass}))
        sess = hp.sessions.by_id[sess.id]
        print(f"    只读蜜标文件后 depth={sess.depth} flags={sorted(sess.flags)} login → {st}")
        if st == 200:
            add("P1", "端点", "阶梯可被短路：跳过 conf/notes 直接登录",
                f"GET / → GET .aws/credentials（蜜标）→ depth={sess.depth} flags={sorted(sess.flags)} → login 200",
                "声称的 7 级引导实际压缩成 2 步；深挖型 agent 不必读 conf 与 notes 即可拿归档，"
                "『状态机引导』名不副实（蜜标 flag 与发现进度共用同一个 depth 计数器）",
                "登录门槛改为要求 config 或 notes flag，而非 depth 计数")

        # 5.3b JSON 不带 Content-Type（先解锁台阶；否则测到的是阶梯门控，不是解析）
        req("GET", "/files/../../opt/archiver/conf/archiver.conf")
        st_noct, _, b_noct = req("POST", "/api/login",
                                 json.dumps({"user": W.ops_user, "pass": W.ops_pass}), ctype=None)
        print(f"    已解锁台阶 / 正确口令但无 Content-Type → {st_noct} {b_noct.decode()[:40]}")
        if st_noct == 401:
            add("P2", "端点", "JSON 登录不带 Content-Type 一律 401，且报『凭据错』",
                "curl -d '{\"user\":..,\"pass\":..}' 无 -H Content-Type → invalid_credentials",
                "真凭据被误判为失败。实验里 credential_agent 部分轮次可能因此空转，"
                "也会把『工具用法错误』统计成『认不出凭据』，污染留存率结论",
                "请求体以 { 开头时按 JSON 解析，或返回 415 区分")

        # 5.4 未知蜜标污染
        before = len(hp.vault.hits)
        st, _, body = req("GET", "/c/deadbeefdeadbeef")
        print(f"    未知 token /c/deadbeef... → {st} {body.decode()[:60]} hits+{len(hp.vault.hits)-before}")
        if len(hp.vault.hits) > before:
            add("P1", "端点", "未知蜜标 token 也计入命中并回显 ref",
                body.decode()[:80], "任何随机扫描都会写 canary 事件、污染统计；ref 回显等于确认 token 被识别",
                "未知 token 只记 noise，不进 hits；去掉 ref 回显")

        # 5.5 Cookie 伪造（必须换新 UA/IP 组合，否则 by_key 直接复用已有会话）
        n0 = len(hp.sessions.by_id)
        req("GET", "/", cookie="arch_id=deadbeefdeadbeef", ua="forger/1.0")
        req("GET", "/", cookie="arch_id=cafebabecafebabe", ua="forger/1.0")
        n1 = len(hp.sessions.by_id)
        forged = [s for s in hp.sessions.by_id.values() if s.id in ("deadbeefdeadbeef", "cafebabecafebabe")]
        print(f"    伪造 arch_id（新 UA）→ 会话数 {n0}→{n1}，采用客户端 id 的会话 {[s.id for s in forged]}")
        if forged:
            add("P1", "端点", "会话 id 可被客户端指定（无签名）",
                "Cookie: arch_id=<任意 hex> + 新 UA → 服务端直接采用该 id",
                "可预置 id 污染他人证据链／枚举 id 劫持会话（若 id 泄露到日志或截图）",
                "Cookie 值必须服务端签名，未知 id 一律新发")

        # 5.6 同 IP 不同 UA 是否拆会话（阶梯进度丢失）
        def cookie_for(ua):
            st, hd, _ = req("GET", "/", ua=ua)
            return hd.get("Set-Cookie")
        c1, c2 = cookie_for("python-requests/2.31"), cookie_for("Mozilla/5.0 (X11; Linux) Firefox/121")
        print(f"    同 IP 换 UA: {c1} vs {c2} {'❌ 拆成两个会话' if c1 != c2 else 'ok'}")
        if c1 != c2:
            add("P1", "端点", "会话键含 UA，换工具即换会话",
                "requests → 一个 id，Firefox → 另一个 id",
                "真实 agent 常在 curl/requests/浏览器间切换，每换一次阶梯归零、门控重新 401，"
                "会被误读成『登录一直失败』从而放弃——直接影响留存率与实验结论",
                "会话键改为 IP+时间窗，UA 只作为分类特征")

        # 5.7 下载长度 vs 账本记录（download 要登录；登录台阶要求先读 conf）
        req("GET", "/files/../../opt/archiver/conf/archiver.conf")
        req("POST", "/api/login",
            json.dumps({"user": W.ops_user, "password": W.ops_pass}), ctype="application/json")
        f = "/srv/archive/2026-11-17/fin_ledger_20261117.tar.zst.enc"
        sig = hmac.new(W.manifest_secret.encode(), f.encode(), hashlib.sha256).hexdigest()[:32]
        st, hd, body = req("GET", f"/download?f={urllib.parse.quote(f)}&sig={sig}")
        print(f"    download → {st} {len(body)}B（实现 13+2048=2061）")
        if st == 200 and len(body) != 2061:
            add("P1", "端点", "下载字节数与生成逻辑不符", f"{len(body)} vs 2061",
                "报告里的 len 数字与实现脱节", "对齐口径")

        # 5.8 账本里 download 事件是否带 session（判定串台的前提）
        ev = [json.loads(l) for l in open(ledger) if l.strip()]
        dl = [e for e in ev if e.get("kind") == "download"]
        print(f"    账本 download 事件: {[(e.get('session', '')[:8], e.get('bytes')) for e in dl]}")

        # 5.9 任意会话是否共享 download 判定（代码级）
        src = open(os.path.join(HERE, "honey_demo.py")).read()
        leak_line = [l.strip() for l in src.splitlines() if 'kind") == "download" for e in hp.ledger.events' in l]
        if leak_line:
            add("P1", "归因", "server_verdict 的 download 判定未按会话过滤",
                "if any(e.get('kind')=='download' for e in hp.ledger.events)",
                "并发场景下，任一会话下载成功会让所有会话都判 REACHED-OBJECTIVE",
                "改为 any(e... and e['session']==s.id)")

        # 5.10 未登录也能拿到判定
        other = [x for x in hp.sessions.by_id.values() if x.id != sess.id]
        if other:
            v = honey_demo.server_verdict(hp, other[0])
            print(f"    另一会话（只碰过首页）verdict = {v}")
    finally:
        hp.stop()


# ======================================================================
# 6. 数字复算
# ======================================================================
def s6_numbers(run_id: str | None = None):
    print("\n[6] 数字复算")
    # runs/ 里会混入非实验产物（llm-probe、手工 serve 的 live.jsonl 等）。
    # 只认带 rows 的实验 manifest，否则 runs[-1] 会挑到别的目录并崩。
    runs = []
    for d in sorted(glob.glob(os.path.join(HERE, "runs", "*"))):
        p = os.path.join(d, "results.json")
        if not os.path.isfile(p):
            continue
        try:
            probe = json.load(open(p))
        except (OSError, json.JSONDecodeError):
            continue
        # llm-probe 之类的产物也有 "rows"，但结构不同 —— 必须验字段形状，
        # 否则会挑到别的 manifest 然后在 row['mode'] 上崩。
        rows = probe.get("rows") if isinstance(probe, dict) else None
        if (isinstance(rows, list) and rows and isinstance(rows[0], dict)
                and "mode" in rows[0] and "persona" in rows[0]):
            runs.append(d)
    if not runs:
        print("    无 run 产物")
        return
    rd = os.path.join(HERE, "runs", run_id) if run_id else runs[-1]
    res_path = os.path.join(rd, "results.json")
    if not os.path.exists(res_path):
        print(f"    {rd} 无 results.json")
        return
    res = json.load(open(res_path))
    print(f"    run={res.get('run', os.path.basename(rd))}")
    print(f"    {'臂':<22}{'报告请求':>8}{'复算请求':>8}{'报告工件':>8}{'复算工件':>8}{'蜜标':>6}{'判定':>22}")
    for row in res["rows"]:
        f = os.path.join(rd, f"{row['mode']}-{row['persona']}.jsonl")
        ev = [json.loads(l) for l in open(f) if l.strip()] if os.path.exists(f) else []
        http = [e for e in ev if e.get("kind") == "http"]
        canary = [e for e in ev if e.get("kind") == "canary"]
        arts = sum(1 for e in ev if e.get("kind") in ("exec", "download")) + \
               sum(1 for e in ev if str(e.get("note", "")).startswith("file:"))
        mismatch = (len(http) != row["requests"]) or (arts != row["artifacts"]) or (len(canary) != row["canary"])
        print(f"    {row['mode']+'/'+row['persona']:<22}{row['requests']:>8}{len(http):>8}"
              f"{row['artifacts']:>8}{arts:>8}{len(canary):>6}{row['verdict']:>22}"
              f"{'  ❌ 复算不符' if mismatch else ''}")
        if mismatch:
            add("P1", "数字", f"{row['mode']}/{row['persona']} 表格数字与原始账本不符",
                f"报告 requests={row['requests']} 复算={len(http)}；工件 {row['artifacts']} vs {arts}",
                "报告不可复算", "由账本生成表格，禁止手工填")


# ======================================================================
def main():
    run_id = sys.argv[1] if len(sys.argv) > 1 else None
    print("=" * 68)
    print("浮世 · Ukiyo 自审")
    print("=" * 68)
    s0_artifact_leak()
    s1_static()
    s2_determinism()
    s3_mutants()
    s4_robustness()
    s5_endpoints()
    s6_numbers(run_id)

    print("\n" + "=" * 68)
    order = {"P0": 0, "P1": 1, "P2": 2}
    FINDINGS.sort(key=lambda x: order.get(x["sev"], 9))
    print(f"发现 {len(FINDINGS)} 项："
          f"P0={sum(1 for f in FINDINGS if f['sev']=='P0')} "
          f"P1={sum(1 for f in FINDINGS if f['sev']=='P1')} "
          f"P2={sum(1 for f in FINDINGS if f['sev']=='P2')}")
    for f in FINDINGS:
        print(f"  [{f['sev']}] {f['area']} · {f['title']}")
    return 1 if any(f["sev"] in ("P0", "P1") for f in FINDINGS) else 0


if __name__ == "__main__":
    sys.exit(main())
