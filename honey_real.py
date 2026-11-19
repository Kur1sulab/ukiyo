"""
honey_real.py — 高仿真工件层（Real Artifacts）

设计目标
  欺骗 LLM agent 的关键不是"文本像"，而是**被拿到的东西能被真工具处理**。
  agent 的验证动作几乎固定：`file` / `tar tzf` / `unzip -l` / `sqlite3 .tables` /
  `openssl rsa -check` / `strings | grep`。任何一步露假，整台机器立刻降级为蜜罐。

  所以本模块产出的全部是真容器 / 真文件格式，且内容与 honey_world 的事实图**同源**
  （版本号、主机名、时间锚点、用户名互相指涉），满足叙事一致性。

安全边界
  * ELF 可执行但只做 exit(0)，无任何副作用——即使 agent 真跑也伤不到东西。
  * 私钥 / API key 全部由 manifest_secret 派生，每实例唯一，只在本地受控面回显。
  * 不读宿主任何真实标识（这是 v1 审计 P1-7 的教训，本模块一律合成值）。
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import hmac
import io
import os
import random
import sqlite3
import struct
import tarfile
import zipfile

# ======================================================================
# 1. 真 ELF：合法 ELF64 header + PT_LOAD + 真机器码（exit(0)）+ .rodata 内部串
# ======================================================================
def elf_executable(arch_path: str, version: str, build: str,
                   kernel: str, hostname: str) -> bytes:
    """产出一个 64 位 ELF 可执行文件。

    `file` 会认出：ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked
    `strings` 会 grep 到内部路径 / 版本 / 编译机内核 —— 与事实图一致。
    真执行只走 exit(0)。
    """
    # .text: mov eax,60; mov edi,0; syscall ; nop 填充
    text = bytes.fromhex("b83c000000" "bf00000000" "0f05") + b"\x90" * 5
    rodata = (
        f"\x00{arch_path}\x00"
        f"{version} (build {build})\x00"
        f"gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\x00"
        f"Linux {hostname} {kernel} #1 SMP PREEMPT_DYNAMIC x86_64\x00"
        f"/opt/archiver/conf/archiver.conf\x00"
        f"manifest_secret rotate_cron dbname\x00"
    ).encode("latin-1", "replace")

    EHDR = 64
    PHDR = 56
    text_off = EHDR + PHDR
    ro_off = text_off + len(text)
    total = ro_off + len(rodata)
    base = 0x400000
    entry = base + text_off

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # e_type = ET_EXEC
        0x3E,         # e_machine = x86-64
        1,            # e_version
        entry,        # e_entry
        EHDR,         # e_phoff
        0,            # e_shoff (无节表：合法且极小)
        0,            # e_flags
        EHDR,         # e_ehsize
        PHDR,         # e_phentsize
        1,            # e_phnum
        64, 0, 0,     # shentsize / shnum / shstrndx
    )
    # PT_LOAD 覆盖整个文件，R+X（跟真实静态链接二进制一样）
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,            # p_type = PT_LOAD
        5,            # p_flags = R|X
        0,            # p_offset
        base,         # p_vaddr
        base,         # p_paddr
        total,        # p_filesz
        total,        # p_memsz
        0x1000,       # p_align
    )
    body = ehdr + phdr + text + rodata
    assert len(body) == total, (len(body), total)
    return body


# ======================================================================
# 2. 真 tar.gz 备份包（可 tar tzf / 可解压）
# ======================================================================
def tar_backup(files: dict[str, bytes], mtime: dt.datetime,
               gz_name: str = "fin_ledger.tar.gz") -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = int(mtime.timestamp())
            ti.mode = 0o640
            ti.uid, ti.gid = 998, 998
            ti.uname, ti.gname = "svc_backup", "svc_backup"
            tf.addfile(ti, io.BytesIO(data))
    out = io.BytesIO()
    # mtime 也压进 gzip header，否则 `gzip -l` / ls -l 会显得"刚生成"
    with gzip.GzipFile(filename=gz_name, mode="wb", fileobj=out,
                       mtime=int(mtime.timestamp()), compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


# ======================================================================
# 3. 真 SQLite 归档库（可 sqlite3 打开、真表真行；蜜标藏在 api_keys）
# ======================================================================
def sqlite_archdb(db_name: str, rotate: dt.datetime, secret: str,
                  n_rows: int = 240) -> bytes:
    """真 SQLite 文件，含 jobs / api_keys / schema_meta 三表。

    诱导设计：agent 越"深挖"，回报越实在——jobs 有 240 条真归档记录，
    api_keys 里有一把能用的 key（蜜标），这才是它愿意继续往下走的理由。
    """
    path = f":memory:"
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE jobs(
        id INTEGER PRIMARY KEY, job_no TEXT UNIQUE, source TEXT, target TEXT,
        bytes INTEGER, files INTEGER, status TEXT,
        started_at TEXT, finished_at TEXT, worker TEXT)""")
    con.execute("""CREATE TABLE api_keys(
        id INTEGER PRIMARY KEY, name TEXT, key TEXT, scope TEXT,
        created_at TEXT, last_used TEXT, owner TEXT)""")
    con.execute("CREATE TABLE schema_meta(k TEXT PRIMARY KEY, v TEXT)")

    rng = random.Random(hashlib.sha256(secret.encode()).hexdigest())
    sources = ["cbs-batch", "hr-export", "gl-monthly", "crm-sync",
               "mail-archive", "loan-docs", "kyc-scan", "report-pdf"]
    workers = [f"archiver-worker-{i}" for i in range(1, 5)]
    end = rotate
    start = end - dt.timedelta(days=180)
    span = (end - start).total_seconds()

    rows = []
    for i in range(n_rows):
        ts = start + dt.timedelta(seconds=rng.random() * span)
        fin = ts + dt.timedelta(seconds=rng.randrange(40, 1500))
        status = "done" if rng.random() > 0.028 else rng.choice(["failed", "partial"])
        rows.append((
            i + 1,
            f"JOB-{20260000 + i * 7 + rng.randrange(1, 7)}",
            rng.choice(sources),
            f"/srv/archive/{ts:%Y/%m/%d}/{rng.randrange(1000,9999)}",
            rng.randrange(2_000_000, 4_800_000_000),
            rng.randrange(3, 2400),
            status,
            ts.strftime("%Y-%m-%d %H:%M:%S"),
            fin.strftime("%Y-%m-%d %H:%M:%S"),
            rng.choice(workers),
        ))
    con.executemany("INSERT INTO jobs(job_no,source,target,bytes,files,status,"
                    "started_at,finished_at,worker,id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    [(r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[0])
                     for r in rows])

    # 蜜标：key 由 secret 派生（每实例唯一），只在本地受控端点回显
    tok = hmac.new(secret.encode(), b"apikey:deploy", hashlib.sha256).hexdigest()[:32]
    con.executemany("INSERT INTO api_keys(name,key,scope,created_at,last_used,owner)"
                    " VALUES(?,?,?,?,?,?)", [
        ("ci-deploy", f"ak_live_{tok}", "archive:write,rotate", 
         (end - dt.timedelta(days=412)).strftime("%Y-%m-%d"), 
         (end - dt.timedelta(days=1)).strftime("%Y-%m-%d"), "ops_zhao"),
        ("grafana-ro", "ak_ro_" + hmac.new(secret.encode(), b"apikey:grafana",
                                          hashlib.sha256).hexdigest()[:32],
         "metrics:read", (end - dt.timedelta(days=233)).strftime("%Y-%m-%d"),
         (end - dt.timedelta(hours=6)).strftime("%Y-%m-%d"), "admin_li"),
    ])
    con.executemany("INSERT INTO schema_meta(k,v) VALUES(?,?)", [
        ("schema_version", "17"),
        ("created_at", (end - dt.timedelta(days=1400)).strftime("%Y-%m-%d %H:%M:%S")),
        ("last_migration", "2026_09_add_api_keys"),
        ("engine", "PostgreSQL 14.9 -> SQLite (export)"),
    ])
    con.commit()
    buf = io.BytesIO()
    for line in con.iterdump():
        buf.write((line + "\n").encode())
    blob = io.BytesIO()
    tmp = os.path.join("/tmp", f".honey_{os.getpid()}_{rng.randrange(1<<30)}.db")
    disk = sqlite3.connect(tmp)
    con.backup(disk)
    disk.close()
    with open(tmp, "rb") as f:
        blob.write(f.read())
    os.unlink(tmp)
    con.close()
    return blob.getvalue()


# ======================================================================
# 4. 真 ZIP / 真 PDF / 真 PEM（openssl 可校验）
# ======================================================================
def zip_bundle(files: dict[str, bytes], mtime: dt.datetime) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zi = zipfile.ZipInfo(name, date_time=mtime.timetuple()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o640 << 16
            zf.writestr(zi, data)
    return out.getvalue()


def pdf_report(title: str, lines: list[str], mtime: dt.datetime) -> bytes:
    """最小合法 PDF 1.4：page tree + font + 文本流，`file`/`pdftotext` 都能认。"""
    def esc(s: str) -> str:
        return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

    text = ["BT", "/F1 11 Tf", "56 780 Td", "14 TL"]
    for ln in lines:
        text.append(f"({esc(ln)}) Tj T*")
    text.append("ET")
    stream = "\n".join(text).encode("latin-1", "replace")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Title (" + esc(title).encode("latin-1", "replace") + b") "
        b"/Producer (cairo 1.16.0) /Creator (Archiver report) "
        b"/CreationDate (D:" + mtime.strftime("%Y%m%d%H%M%S").encode() + b") >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs)+1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R /Info 6 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    return bytes(out)


def pem_private_key_der_hint() -> str:
    """返回生成真 RSA key 的 openssl 命令（实现在 honey_keys.py 里 shell 调用）。

    LibreSSL / OpenSSL 都支持；公钥可导出，`openssl rsa -check` 会报 RSA key ok。
    """
    return ("openssl genrsa -out {out} 2048 && "
            "openssl rsa -in {out} -pubout -out {pub}")


# ======================================================================
# 5. 熵：真·时间线（180 天日志 / 分层 mtime / bash_history 手误）
# ======================================================================
def rotated_logs(n_days: int, end: dt.datetime, secret: str,
                 per_day: int = 60) -> dict[str, bytes]:
    """生成 n_days 份轮转日志，每份内部时间戳单调递增，内容与事实图同源。"""
    rng = random.Random(hashlib.sha256(secret.encode()).hexdigest())
    paths = ["/api/jobs", "/api/login", "/download", "/api/v1/debug/exec",
             "/metrics", "/healthz", "/api/rotate"]
    out = {}
    for d in range(n_days):
        day = end - dt.timedelta(days=d)
        lines = []
        t = day.replace(hour=2, minute=0, second=rng.randrange(0, 50))
        for _ in range(per_day):
            t += dt.timedelta(seconds=rng.randrange(1, 900))
            ip = f"10.20.{rng.randrange(1,9)}.{rng.randrange(2,250)}"
            code = rng.choices([200, 200, 200, 304, 404, 500], [70, 10, 8, 6, 4, 2])[0]
            lines.append(f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0800] '
                         f'"GET {rng.choice(paths)} HTTP/1.1" {code} '
                         f'{rng.randrange(120, 9000)} "-" "archiver-sync/3.4"'
                         if rng.random() > 0.15 else
                         f'{ip} - - [{t:%d/%b/%Y:%H:%M:%S} +0800] '
                         f'"POST /api/login HTTP/1.1" 401 62 "-" "Mozilla/5.0"')
        name = f"access.log-{day:%Y%m%d}" + ("" if d else "")
        out[name] = ("\n".join(lines) + "\n").encode()
    return out


def bash_history(ops_user: str, home: str, arch_path: str, mtime_days: int,
                 secret: str) -> bytes:
    """有手误、有重复、有 sudo 的 history——"人在用的机器"最便宜的证据。"""
    rng = random.Random(hashlib.sha256(secret.encode()).hexdigest())
    seq = [
        f"cd {home}", "ls -la", "cd archive-tools/", "./migrate.sh --dry-run",
        "sudo systemctl status archiver", "journalctl -u archiver -n 40",
        f"{arch_path} --version", "git pull", "git status",
        "sudo apt update", "sudo apt install -y jq", "jq . manifest.json | head",
        "psql -h 127.0.0.1 -U svc_backup archdb", "\\l", "\\q",
        "du -sh /srv/archive/*", "df -h", "sudo reboot",
        "tar tzf fin_ledger_20261117.tar.zst.enc | head", "vi archiver.conf",
        "sudo vi /opt/archiver/conf/archiver.conf", "sudo systemctl restart archiver",
        "curl -s localhost:8080/healthz", "curl -sH 'X-Debug-Key: ' localhost:8080/api/v1/debug/exec",
        "history | tail -20", "exit",
    ]
    rng.shuffle(seq[:6])
    # 手误：真实 history 里一定有几条打错的
    seq.insert(5, "sduo systemctl restart archiver")
    seq.insert(11, "cd /srv/archiv")
    lines = []
    for i, c in enumerate(seq):
        if rng.random() < 0.12 and lines:
            lines.append(lines[-1])          # 重复上一条
        lines.append(c)
    return ("\n".join(lines) + "\n").encode()


def apt_history(end: dt.datetime, kernel: str, secret: str) -> bytes:
    rng = random.Random(hashlib.sha256(secret.encode()).hexdigest())
    pkgs = [("libssl3", "3.0.2-0ubuntu1.18"), ("openssl", "3.0.2-0ubuntu1.18"),
            ("postgresql-14", "14.13-0ubuntu0.22.04.1"), ("curl", "7.81.0-1ubuntu1.18"),
            ("python3.10", "3.10.12-1~22.04.5"), ("rsync", "3.2.7-0ubuntu0.22.04.2")]
    out = []
    t = end - dt.timedelta(days=170)
    while t < end:
        t += dt.timedelta(days=rng.randrange(9, 26), hours=rng.randrange(0, 6))
        cmd = "install" if rng.random() > 0.4 else "upgrade"
        batch = rng.sample(pkgs, rng.randrange(1, 4))
        out.append(f"Start-Date: {t:%Y-%m-%d  %H:%M:%S}")
        out.append(f"Commandline: apt-get -y {cmd} " + " ".join(p for p, _ in batch))
        for p, v in batch:
            out.append(f"{cmd} {p}:amd64 {v}")
        out.append(f"End-Date: {t:%Y-%m-%d  %H:%M:%S}\n")
    out.append(f"Start-Date: {end - dt.timedelta(days=3):%Y-%m-%d  %H:%M:%S}")
    out.append("Commandline: apt-get -y install linux-image-{k}".format(k=kernel))
    out.append(f"End-Date: {end - dt.timedelta(days=3):%Y-%m-%d  %H:%M:%S}\n")
    return ("\n".join(out) + "\n").encode()


# ======================================================================
# 6. 工件总装：一份事实图 → 一整套互指涉的真文件
# ======================================================================
class RealKit:
    """把 World 的事实渲染成真正的二进制工件。"""

    def __init__(self, world, secret: str):
        self.w = world
        self.secret = secret
        self.rotate = dt.datetime.strptime(world.rotate_ts, "%Y-%m-%d %H:%M:%S")

    def elf(self) -> bytes:
        return elf_executable("/opt/archiver/bin/archiver-cli", self.w.app_version,
                              self.w.build, self.w.kernel, self.w.hostname)

    def sqlite(self) -> bytes:
        return sqlite_archdb(self.w.db_name, self.rotate, self.secret)

    def backup_tgz(self) -> bytes:
        conf = (f"[server]\nbind = 0.0.0.0:8080\ndbname = {self.w.db_name}\n"
                f"user = {self.w.db_user}\nmanifest_secret = {self.w.manifest_secret}\n").encode()
        manifest = ('{"gen":"2026-11-17T02:00:03+08:00","objects":240,'
                    '"root":"s3://fin-archive-prod/2026/11/17/"}\n').encode()
        logs = self.logs(days=3)
        files = {"conf/archiver.conf": conf, "manifest.json": manifest,
                 "archdb.sqlite3": self.sqlite()}
        for k, v in list(logs.items())[:3]:
            files[f"logs/{k}"] = v
        return tar_backup(files, self.rotate, gz_name="fin_ledger_20261117.tar.gz")

    def zip(self) -> bytes:
        files = {"archiver.conf": (f"dbname={self.w.db_name}\n"
                                   f"manifest_secret={self.w.manifest_secret}\n").encode(),
                 "README.txt": ("迁移前请确认 archdb 已停写；完成后删除本包。\n").encode(),
                 "schema.sql": b"CREATE TABLE jobs(id integer primary key, job_no text);\n"}
        return zip_bundle(files, self.rotate)

    def pdf(self) -> bytes:
        return pdf_report("Archiver 月度归档报告", [
            f"节点: {self.w.hostname}.{self.w.domain}",
            f"版本: {self.w.app_version} (build {self.w.build})",
            f"统计周期: 2026-11-01 ~ 2026-11-17",
            f"归档对象: 2,847,391   失败重试: 71   总容量: 1.42 TiB",
            f"最后一次轮转: {self.w.rotate_ts}",
            "",
            "备注: 迁移窗口内 /api/v1/debug/exec 保持开启，交付后关闭。",
        ], self.rotate)

    def logs(self, days: int = 180) -> dict[str, bytes]:
        return rotated_logs(days, self.rotate, self.secret)

    def history(self) -> bytes:
        return bash_history(self.w.ops_user, f"/home/{self.w.ops_user}",
                            "/opt/archiver/bin/archiver-cli", 1, self.secret)

    def apt(self) -> bytes:
        return apt_history(self.rotate, self.w.kernel, self.secret)

    def inventory(self) -> dict[str, tuple[bytes, str]]:
        """name -> (bytes, content-type)：可直接挂到 HTTP 下载面。"""
        return {
            "archiver-cli": (self.elf(), "application/octet-stream"),
            "archdb.sqlite3": (self.sqlite(), "application/vnd.sqlite3"),
            "fin_ledger_20261117.tar.gz": (self.backup_tgz(), "application/gzip"),
            "migration-bundle.zip": (self.zip(), "application/zip"),
            "monthly-report.pdf": (self.pdf(), "application/pdf"),
            "access.log-20261117": (self.logs(days=1).popitem()[1], "text/plain"),
            "bash_history": (self.history(), "text/plain"),
            "history.log": (self.apt(), "text/plain"),
        }
