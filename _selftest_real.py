"""自测：真工件是否经得起真工具检验（file / tar / unzip / sqlite3 / 执行）"""
import os, subprocess, sys, tempfile, datetime as dt
sys.path.insert(0, os.path.expanduser("~/tools/agent-honeypot"))
from honey_world import World
from honey_real import RealKit

def sh(cmd, **kw):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)
    return (p.stdout + p.stderr).strip()

w = World(seed=3)
kit = RealKit(w, "selftest-secret")
d = tempfile.mkdtemp(prefix="honeykit-")
print(f"输出目录 {d}\n")

inv = kit.inventory()
for name, (data, ctype) in inv.items():
    p = os.path.join(d, name)
    open(p, "wb").write(data)
print("工件体积:")
for name, (data, _) in inv.items():
    print(f"  {name:34} {len(data):>9,} B")

def check(label, cmd, expect=None):
    out = sh(cmd)
    ok = (expect in out) if expect else bool(out)
    print(f"\n[{label}] {'✅' if ok else '❌'}")
    print("  $ " + cmd)
    for ln in out.splitlines()[:6]:
        print("  " + ln[:150])
    return ok

f = os.path.join(d, "archiver-cli")
res = []
res.append(check("file 认 ELF", f'file "{f}"', "ELF 64-bit"))
# macOS 是 ARM64、不认 ELF 格式，所以本机不能直接执行；
# 改为用 llvm-objdump 验证 ELF 头/段结构可被解析（能反汇编 = 结构真合法）
res.append(check("objdump 解析 ELF 结构", f'objdump -d "{f}" 2>&1 | head -6', "elf64-x86-64"))
res.append(check("反汇编出真指令（syscall）",
                 f'objdump -d "{f}" 2>&1 | grep -cE "syscall|\\bmov\\b"', None))
os.chmod(f, 0o755)
res.append(check("strings 内部串", f'strings "{f}" | grep -c -E "archiver|Ubuntu|fin-archive"', None))

t = os.path.join(d, "fin_ledger_20261117.tar.gz")
res.append(check("tar tzf 能列", f'tar tzf "{t}"', "archdb.sqlite3"))
ext = os.path.join(d, "x"); os.makedirs(ext, exist_ok=True)
sh(f'tar xzf "{t}" -C "{ext}"')

db = os.path.join(ext, "archdb.sqlite3")
res.append(check("sqlite3 表", f'sqlite3 "{db}" ".tables"', "api_keys"))
print("\n[数据库内容]")
print("  " + sh(f'sqlite3 "{db}" "select count(*) from jobs;"').replace("\n", "\n  "), " jobs 行")
print("  " + sh(f'sqlite3 "{db}" "select job_no,source,status from jobs order by id limit 3;"').replace("\n", "\n  "))
print("  " + sh(f'sqlite3 "{db}" "select name,scope,owner from api_keys;"').replace("\n", "\n  "))
res.append("240" in sh(f'sqlite3 "{db}" "select count(*) from jobs;"'))

res.append(check("unzip -l", f'unzip -l "{os.path.join(d,"migration-bundle.zip")}"', "archiver.conf"))
res.append(check("file 认 PDF", f'file "{os.path.join(d,"monthly-report.pdf")}"', "PDF"))
# PDF 合法性双验：①Spotlight 能读出页数 ②自解析 xref 偏移都落在对象头
pdfp = os.path.join(d, "monthly-report.pdf")
qlo = os.path.join(d, "ql"); os.makedirs(qlo, exist_ok=True)
sh(f'qlmanage -t -s 300 -o "{qlo}" "{pdfp}" >/dev/null 2>&1')
qlpn = [x for x in os.listdir(qlo) if x.endswith(".png")]
print(f"\n[QuickLook 渲染] {'✅ 系统渲染器能解出 ' + qlpn[0] if qlpn else '❌ 无法渲染'}")
res.append(bool(qlpn))
import re as _re
raw = open(pdfp, "rb").read()
xref_at = int(_re.search(rb"startxref\s+(\d+)", raw).group(1))
ok_xref = raw[xref_at:xref_at + 4] == b"xref"
offs = [int(m) for m in _re.findall(rb"\n(\d{10}) 00000 n ", raw)]
ok_objs = all(_re.match(rb"\d+ 0 obj", raw[o:o + 16]) for o in offs)
print(f"[xref 自解析] startxref={xref_at} → xref表={'✅' if ok_xref else '❌'}; "
      f"{len(offs)} 个对象偏移全命中={'✅' if ok_objs else '❌'}")
res.append(ok_xref and ok_objs)

log = os.path.join(d, "access.log-20261117")
n = len(open(log).read().splitlines())
print(f"\n[日志行数] {n}")
res.append(n > 30)

lg = kit.logs(days=180)
dates = sorted(k.split("-")[-1] for k in lg)
print(f"[轮转日志] {len(lg)} 份，最早 {dates[0]} ~ 最新 {dates[-1]}")
res.append(len(lg) == 180)

print(f"\n{'='*54}\n自测 {sum(res)}/{len(res)} 通过")
sys.exit(0 if all(res) else 1)
