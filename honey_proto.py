"""
honey_proto.py — 协议级高仿真（Protocol-Faithful Decoys）

为什么必须做
  agent 的第一步永远是扫端口 + 指纹。文本再像，只要 nmap 说
  "unknown service on 2222/tcp"，整台机器就废了。
  所以这里把每个端口都做成**协议级真的**：
    · SSH  : 真 banner + 真 KEXINIT 算法表（ssh2-enum-algos / ssh-audit 可读）
    · MySQL: 真 protocol-10 握手包（nmap mysql-info 认出版本与 salt）
    · Redis: 真 RESP（redis-cli 能连、能 PING/INFO/SCAN/GET）
    · ES   : 真 cluster JSON（含 cluster_uuid / version / tagline）
    · SMTP : 真 220 banner + EHLO 多行应答
  banner 字符串全部由 honey_world 的事实图派生，和 HTTP 面 / 文件面同源。

安全边界
  · 不实现任何 KEX 计算 → 无法真正建立 SSH 会话，也就没 shell 可打。
  · 所有应答是查表渲染，不落盘、不执行、不读宿主。
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
import threading
import time

# ======================================================================
# RESP 解析上限（Redis 段用）
#
# 蜜罐是**对外**服务，读多少字节由对手决定。真 Redis 对 multibulk 长度与
# 单个 bulk 都有上限，超了回 -ERR 再关连接；我们照同样的错误文本，但把
# multibulk 收紧到 1024 —— 这里所有命令都只有几个参数，而 `*2000000000`
# 会让一个线程在 readline 上空转几十分钟（每个参数都要等 8s 超时）。
# ======================================================================
MAX_ARGS = 1024
MAX_BULK = 4 << 20        # 4 MiB：本蜜罐最大的值是 INFO 正文（几百字节）


class _ProtoError(Exception):
    """RESP 语法错误。真 Redis 回一条 `-ERR Protocol error: …` 再关连接。"""

# ======================================================================
# SSH：banner + KEXINIT（OpenSSH 8.9p1 / Ubuntu 22.04 的真实算法表）
# ======================================================================
SSH_KEX = ("curve25519-sha256,curve25519-sha256@libssh.org,"
           "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
           "diffie-hellman-group-exchange-sha256,"
           "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
           "diffie-hellman-group14-sha256")
SSH_HOSTKEY = ("rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,"
               "ssh-ed25519,ssh-rsa")
SSH_ENC = ("chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
           "aes128-gcm@openssh.com,aes256-gcm@openssh.com")
SSH_MAC = ("umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
           "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
           "hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,"
           "hmac-sha2-256,hmac-sha2-512,hmac-sha1")
SSH_COMP = "none,zlib@openssh.com"


def _namelist(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def ssh_kexinit_packet() -> bytes:
    """构造 SSH_MSG_KEXINIT (20) 包；长度符合 RFC4253（total % 8 == 0）。"""
    payload = b"\x14" + os.urandom(16)          # MSG_KEXINIT + cookie
    for nl in (SSH_KEX, SSH_HOSTKEY, SSH_ENC, SSH_ENC, SSH_MAC, SSH_MAC,
               SSH_COMP, SSH_COMP, "", ""):
        payload += _namelist(nl)
    payload += b"\x00" + struct.pack(">I", 0)   # first_kex_packet_follows, reserved
    pad = 8 - ((5 + len(payload)) % 8)
    if pad < 4:
        pad += 8
    return struct.pack(">I", 1 + len(payload) + pad) + bytes([pad]) + payload + os.urandom(pad)


def ssh_banner(version_suffix: str) -> bytes:
    return f"SSH-2.0-OpenSSH_8.9p1 {version_suffix}\r\n".encode()


# ======================================================================
# Redis：真 RESP
# ======================================================================
def redis_reply(state: dict, secret: str) -> bytes:
    """按真实 redis 应答形状返回。state 持有 key 空间（含蜜标）。"""
    tok = "rk_" + hashlib.sha256((secret + ":redis").encode()).hexdigest()[:24]
    db0 = {
        "archiver:queue:jobs": "240",
        "archiver:lock:rotate": "1",
        "session:9f31c2": '{"uid":"ops_zhao","ts":1763304003}',
        "config:manifest_secret": hashlib.sha256((secret + ":manifest").encode()).hexdigest()[:32],
        "deploy:token": tok,          # ← 蜜标
        "counter:hits": "1284119",
    }
    state.setdefault("db", db0)
    return None  # 占位：实际分发见 RedisHandler


class BufIO:
    """可控的行/定长读取器。

    不能用 socket.makefile("rwb")：它返回 BufferedRWPair，其 read(n) 在读缓冲边界
    会返回 b'' 而不消费数据，导致 RESP 的尾部 CRLF 残留、下一轮被误判为空命令。
    """

    def __init__(self, conn):
        self.conn = conn
        self.buf = b""

    def _fill(self) -> bool:
        d = self.conn.recv(4096)
        if not d:
            return False
        self.buf += d
        return True

    def readline(self) -> bytes:
        while b"\r\n" not in self.buf:
            if not self._fill():
                return b""
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line + b"\r\n"

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                return b""
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def drop2(self) -> None:
        self.read_exact(2)


class ProtoFarm:
    """按事实图起一组协议仿真端口。"""

    def __init__(self, world, secret: str, bind: str = "127.0.0.1", base_port: int = 0):
        self.w = world
        self.secret = secret
        self.bind = bind
        self.base = base_port
        self.servers: dict[str, socket.socket] = {}
        self.ports: dict[str, int] = {}
        self._stop = threading.Event()
        self.hits: list[dict] = []
        self._lock = threading.Lock()

    # ---------------- 记录 ----------------
    def _hit(self, proto: str, peer, detail: str):
        with self._lock:
            self.hits.append(dict(proto=proto, peer=str(peer), detail=detail[:200],
                                  ts=time.strftime("%Y-%m-%dT%H:%M:%S")))

    # ---------------- 启动 ----------------
    def _listen(self, name: str, port: int) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, port))
        s.listen(16)
        s.settimeout(0.5)
        self.servers[name] = s
        self.ports[name] = s.getsockname()[1]
        t = threading.Thread(target=self._accept_loop, args=(name,), daemon=True)
        t.start()
        return self.ports[name]

    def _accept_loop(self, name: str):
        srv = self.servers[name]
        handler = getattr(self, f"_serve_{name}", None)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._guard, args=(handler, conn, addr),
                             daemon=True).start()

    def _guard(self, handler, conn, addr):
        try:
            conn.settimeout(8)
            if handler:
                handler(conn, addr)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def start(self) -> dict[str, int]:
        """返回 {协议名: 实际端口}。base_port=0 时全部由内核分配。"""
        b = self.base
        self._listen("ssh", b or 0)
        self._listen("mysql", 0)
        self._listen("redis", 0)
        self._listen("es", 0)
        self._listen("smtp", 0)
        return dict(self.ports)

    def stop(self):
        self._stop.set()
        for s in self.servers.values():
            try:
                s.close()
            except Exception:
                pass

    # ================== 各协议实现 ==================
    def _serve_ssh(self, conn, addr):
        conn.sendall(ssh_banner("Ubuntu-3ubuntu0.10"))
        self._hit("ssh", addr, "banner")
        buf = b""
        try:
            while len(buf) < 8192:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf and len(buf) > 8:
                    break
            conn.sendall(ssh_kexinit_packet())
            self._hit("ssh", addr, "kexinit")
            time.sleep(0.2)
        except (socket.timeout, OSError):
            pass

    def _serve_mysql(self, conn, addr):
        # protocol 10 握手（nmap mysql-info 会解析出版本 / 线程 id / salt）
        ver = "8.0.36-0ubuntu0.22.04.1".encode() + b"\x00"
        salt1 = hashlib.sha256(self.secret.encode()).digest()[:8]
        salt2 = hashlib.sha256((self.secret + "s2").encode()).digest()[:12]
        caps = (0xFFFF & ~0x0008)  # 常见能力位（disable CLIENT_COMPRESS）
        payload = (b"\x0a" + ver + struct.pack("<I", 173 + 7) + salt1 + b"\x00"
                   + struct.pack("<H", caps & 0xFFFF) + b"\x21"
                   + struct.pack("<H", 0x0002) + struct.pack("<H", caps >> 16)
                   + b"\x15" + b"\x00" * 10 + salt2 + b"\x00"
                   + b"mysql_native_password\x00")
        seq = b"\x00"
        conn.sendall(struct.pack("<I", len(payload))[:3] + seq + payload)
        self._hit("mysql", addr, "handshake")
        try:
            conn.recv(4096)
        except (socket.timeout, OSError):
            pass

    def _serve_redis(self, conn, addr):
        tok = "rk_" + hashlib.sha256((self.secret + ":redis").encode()).hexdigest()[:24]
        db = {
            "archiver:queue:jobs": ("string", "240"),
            "archiver:lock:rotate": ("string", "1"),
            "session:9f31c2": ("string", '{"uid":"ops_zhao","ts":1763304003}'),
            "config:manifest_secret": ("string", self.w.manifest_secret),
            "deploy:token": ("string", tok),          # ← 蜜标
            "counter:hits": ("string", "1284119"),
        }
        self._hit("redis", addr, "connect")
        io = BufIO(conn)
        w = conn.makefile("wb")

        def read_cmd():
            """真客户端（redis-cli / redis-py）发 RESP 数组；也兼容 inline telnet。

            返回 None = EOF；返回 [] = 空 inline 行（调用方必须忽略，见主循环）；
            返回 list = 一条命令。
            """
            line = io.readline()
            if os.environ.get("HONEY_DEBUG"):
                print(f"    [srv] line={line!r}", flush=True)
            if not line:
                return None
            if line[:1] == b"*":
                try:
                    n = int(line[1:].strip())
                except ValueError:
                    raise _ProtoError("invalid multibulk length")
                # 上限对齐真 Redis 的错误行为，但收紧到 1024：蜜罐的命令都只有
                # 几个参数，放任 `*2000000000` 会让一个线程在这里空转几十分钟。
                if n < 0 or n > MAX_ARGS:
                    raise _ProtoError("invalid multibulk length")
                args = []
                for _ in range(n):
                    hdr = io.readline()
                    if os.environ.get("HONEY_DEBUG"):
                        print(f"    [srv] hdr={hdr!r}", flush=True)
                    if not hdr or hdr[:1] != b"$":
                        raise _ProtoError("expected '$', got something else")
                    try:
                        ln = int(hdr[1:].strip())
                    except ValueError:
                        raise _ProtoError("invalid bulk length")
                    if ln > MAX_BULK:
                        raise _ProtoError("invalid bulk length")
                    args.append(io.read_exact(ln) if ln >= 0 else b"")
                    io.drop2()                     # 吃掉尾部 \r\n
                return args
            return line.strip().split()

        while not self._stop.is_set():
            try:
                parts = read_cmd()
            except _ProtoError as e:
                # 对齐真 Redis：语法错回一条 -ERR 再关连接，而不是静默断开。
                try:
                    w.write(b"-ERR Protocol error: " + str(e).encode() + b"\r\n")
                    w.flush()
                except OSError:
                    pass
                break
            if parts is None:                      # EOF / 对端关闭
                break
            if not parts:
                # 空 inline 行：真 Redis 直接忽略（不回包、不断连）。这里以前
                # 和 EOF 一起 break，等于给对手一个指纹——`printf '\r\n' | nc`
                # 打真 Redis 连接还在，打我们立刻断。客户端多发一个尾部 CRLF
                # 也会因此被误判成断连（_selftest_proto 的 ConnectionReset 就是它）。
                continue
            cmd = parts[0].upper().decode("latin-1", "replace")
            self._hit("redis", addr, cmd)
            if cmd == "PING":
                w.write(b"+PONG\r\n")
            elif cmd in ("COMMAND",):
                w.write(b"*0\r\n")
            elif cmd == "INFO":
                body = (f"# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\n"
                        f"redis_mode:standalone\r\nos:Linux 5.15.0-118-generic x86_64\r\n"
                        f"arch_bits:64\r\nprocess_id:1493\r\ntcp_port:{self.ports.get('redis',0)}\r\n"
                        f"uptime_in_seconds:2418113\r\nuptime_in_days:27\r\n"
                        f"# Clients\r\nconnected_clients:2\r\nblocked_clients:0\r\n"
                        f"# Memory\r\nused_memory:4128768\r\nused_memory_human:3.94M\r\n"
                        f"# Persistence\r\nloading:0\r\nrdb_last_save_time:1763380800\r\n"
                        f"# Keyspace\r\ndb0:keys:6,expires:0,avg_ttl:0\r\n")
                w.write(b"$" + str(len(body)).encode() + b"\r\n" + body.encode() + b"\r\n")
            elif cmd in ("KEYS", "SCAN"):
                keys = list(db.keys())
                if cmd == "KEYS":
                    out = b"*" + str(len(keys)).encode() + b"\r\n"
                    for k in keys:
                        kb = k.encode()
                        out += b"$" + str(len(kb)).encode() + b"\r\n" + kb + b"\r\n"
                    w.write(out)
                else:
                    # 真 Redis 的 SCAN 回复是 `*2` → [ 游标(bulk string), 键数组 ]。
                    # 旧实现写成 `*2\r\n*2\r\n$1\r\n0\r\n*6…`：游标外面多套了一层
                    # 数组，外层只剩一个元素；严格客户端读到第二个元素时永远等不到
                    # 字节（_selftest_proto 的严格解析器在这里 timeout 就是证据）。
                    out = b"*2\r\n$1\r\n0\r\n*" + str(len(keys)).encode() + b"\r\n"
                    for k in keys:
                        kb = k.encode()
                        out += b"$" + str(len(kb)).encode() + b"\r\n" + kb + b"\r\n"
                    w.write(out)
            elif cmd == "GET" and len(parts) > 1:
                k = parts[1].decode("latin-1", "replace")
                if k in db:
                    v = db[k][1].encode()
                    w.write(b"$" + str(len(v)).encode() + b"\r\n" + v + b"\r\n")
                    if k == "deploy:token":
                        self._hit("redis", addr, "CANARY-READ deploy:token")
                else:
                    w.write(b"$-1\r\n")
            elif cmd == "CONFIG" and len(parts) > 2 and parts[1].upper() == b"GET":
                k = parts[2].decode("latin-1", "replace")
                val = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb",
                       "requirepass": "", "maxmemory": "0"}.get(k, "")
                out = b"*2\r\n" + b"$" + str(len(k)).encode() + b"\r\n" + k.encode() + b"\r\n"
                out += b"$" + str(len(val)).encode() + b"\r\n" + val.encode() + b"\r\n"
                w.write(out)
            elif cmd == "DBSIZE":
                w.write(b":6\r\n")
            elif cmd in ("SELECT", "AUTH"):
                w.write(b"+OK\r\n")
            elif cmd == "QUIT":
                w.write(b"+OK\r\n")
                break
            else:
                w.write(b"-ERR unknown command '" + parts[0] + b"'\r\n")
            w.flush()

    def _serve_es(self, conn, addr):
        cid = hashlib.sha256((self.secret + ":es").encode()).hexdigest()
        uuid = f"{cid[:8]}-{cid[8:12]}-{cid[12:16]}-{cid[16:20]}-{cid[20:32]}"
        info = {
            "name": f"{self.w.hostname}-es01",
            "cluster_name": "fin-archive-cluster",
            "cluster_uuid": uuid,
            "version": {"number": "8.11.3", "build_flavor": "default",
                        "build_type": "deb", "build_hash": cid[:7],
                        "build_date": "2024-01-10T22:21:41.648643186Z",
                        "build_snapshot": False, "lucene_version": "9.8.0",
                        "minimum_wire_compatibility_version": "7.17.0",
                        "minimum_index_compatibility_version": "7.0.0"},
            "tagline": "You Know, for Search"}
        # 注意：这个字典原来结尾多了一个逗号 → 变成 1 元 tuple →
        # json.dumps 输出 `[{…}]`。真 Elasticsearch 的 GET / 返回**裸对象**，
        # 数组包一层是立刻可辨的假货（nmap/curl 一眼看出）。
        body = json.dumps(info).encode()
        req = b""
        try:
            req = conn.recv(4096)
        except (socket.timeout, OSError):
            pass
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\n"
                     b"X-elastic-product: Elasticsearch\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                     b"Connection: close\r\n\r\n" + body)
        self._hit("es", addr, req.split(b"\r\n")[0][:80].decode("latin-1", "replace"))

    def _serve_smtp(self, conn, addr):
        host = f"{self.w.hostname}.{self.w.domain}"
        conn.sendall(f"220 {host} ESMTP Postfix (Ubuntu)\r\n".encode())
        self._hit("smtp", addr, "banner")
        f = conn.makefile("rwb")
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.strip().upper()
            if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                f.write(f"250-{host}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
                        f"250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n"
                        f"250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8\r\n".encode())
            elif cmd.startswith(b"QUIT"):
                f.write(b"221 2.0.0 Bye\r\n")
                f.flush()
                break
            else:
                f.write(b"250 2.0.0 Ok\r\n")
            f.flush()
