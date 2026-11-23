"""协议层自测：用真客户端 + nmap -sV 判定是否被识别为真服务"""
import json, os, socket, struct, subprocess, sys, time
# 从**本文件所在目录**导入，而不是 /tools/agent-honeypot 这个软链：
# 在容器/CI/副本里跑时软链不存在，自测会 import 到另一棵树或直接失败。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from honey_world import World
from honey_proto import ProtoFarm, ssh_kexinit_packet

w = World(seed=3)
farm = ProtoFarm(w, "selftest-secret", bind="127.0.0.1")
ports = farm.start()
print("端口:", json.dumps(ports, ensure_ascii=False))
time.sleep(0.3)
res = {}

# ---- SSH: banner + KEXINIT 包结构 ----
s = socket.create_connection(("127.0.0.1", ports["ssh"]), 3)
s.settimeout(3)
banner = s.recv(256)
s.sendall(b"SSH-2.0-selftest\r\n")
time.sleep(0.3)
kex = s.recv(4096)
s.close()
pkt_len = struct.unpack(">I", kex[:4])[0]
pad_len = kex[4]
ok_pad = (4 + pkt_len) % 8 == 0 and 4 <= pad_len <= 255
print(f"\n[SSH banner] {banner!r}")
print(f"[SSH KEXINIT] 包长={pkt_len} pad={pad_len} total%8={((4+pkt_len)%8)} msg={kex[5]}(20=KEXINIT) "
      f"{'✅' if ok_pad and kex[5]==20 else '❌'}")
res["ssh"] = b"OpenSSH_8.9p1" in banner and ok_pad and kex[5] == 20

# ---- MySQL: 解析握手 ----
s = socket.create_connection(("127.0.0.1", ports["mysql"]), 3)
hs = s.recv(256); s.close()
hlen = struct.unpack("<I", hs[:3] + b"\x00")[0]
proto = hs[4]
end = hs.index(b"\x00", 5)
ver = hs[5:end].decode()
print(f"\n[MySQL] protocol={proto} version={ver!r} 包长={hlen}")
res["mysql"] = proto == 10 and ver.startswith("8.0.36")

# ---- Redis: 严格 RESP 解析 + 原始字节留证 ----
# 不用 socket.makefile("rwb")：BufferedRWPair 的 read(n) 在缓冲边界会返回 b""
# 而**不消费数据**，客户端以为拿到回复、实际拿到空串，下一条 readline 才炸成
# ConnectionReset —— 这正是本次故障的现场。这里改成按 RESP 语法逐字节读，
# 同时把原始接收字节留证，报告里贴的就是这些字节。

class RespReader:
    """只做一件事：按 RESP 语法从 socket 上读**一条**完整回复，并留原文。"""

    def __init__(self, sock):
        self.s = sock
        self.buf = b""
        self.raw = b""

    def _fill(self):
        c = self.s.recv(4096)
        if not c:
            raise EOFError("对端关闭了连接（RESP 回复不完整）")
        self.raw += c
        self.buf += c

    def line(self) -> bytes:
        while b"\r\n" not in self.buf:
            self._fill()
        ln, self.buf = self.buf.split(b"\r\n", 1)
        return ln

    def exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        d, self.buf = self.buf[:n], self.buf[n:]
        return d

    def reply(self):
        """返回 (类型头, 值)。数组递归。任何长度/尾部不符就抛错，不静默跳过。"""
        h = self.line()
        t, rest = h[:1], h[1:]
        if t in (b"+", b"-", b":"):
            return t.decode(), rest.decode("latin-1")
        if t == b"$":
            n = int(rest)
            if n < 0:                      # $-1 = nil
                return "$", None
            body = self.exact(n)
            if self.exact(2) != b"\r\n":
                raise ValueError(f"bulk 尾部不是 CRLF（声明长度 {n}）")
            return "$", body.decode("latin-1")
        if t == b"*":
            n = int(rest)
            return "*", [self.reply() for _ in range(max(n, 0))]
        raise ValueError(f"未知 RESP 类型头 {h!r}")


def frame(*args: str) -> bytes:
    """构造一条 RESP 数组命令。

    **结尾不许再补 CRLF**：每个 bulk string 自带的尾部 CRLF 就是整条命令的结尾。
    旧脚本在 join 之后又加了 b"\\r\\n"，于是每条命令后面跟一个空 inline 行 ——
    真 Redis 会忽略它，但当时我们的服务端把它当成断连信号。
    """
    out = b"*%d\r\n" % len(args)
    for a in args:
        b = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(b), b)
    return out


def redis_conn(port):
    s = socket.create_connection(("127.0.0.1", port), 3)
    s.settimeout(3)
    return s, RespReader(s)


rchecks: list[tuple[str, bool, str]] = []


def rcheck(label: str, ok: bool, detail: str = "") -> None:
    rchecks.append((label, ok, detail))
    print(f"  [{'✅' if ok else '❌'}] {label}" + (f"　{detail}" if detail else ""))


class _StopRedis(Exception):
    """Redis 段某一步读失败：已记成失败断言，跳过剩余步骤继续跑别的协议。"""


def take(label: str):
    """有界读一条 RESP 回复。

    每次 recv 都受 settimeout(3) 约束：超时就抛 socket.timeout，由这里转成
    **一条失败的显式断言**（带具体错因），而不是让脚本静默挂住或裸崩栈。
    上一版正是在这里挂死：客户端多发了一个 CRLF，服务端把它当断连信号关了
    连接，下一次 readline 永远等不到字节。
    """
    try:
        return r.reply()
    except socket.timeout:
        rcheck(label, False, "3s 内未收到完整回复（服务端挂住或提前关连接）")
    except (EOFError, ConnectionResetError) as e:
        rcheck(label, False, f"{type(e).__name__}: {e}（对端提前关闭）")
    except ValueError as e:
        rcheck(label, False, f"RESP 结构非法: {e}")
    raise _StopRedis


print("\n[Redis] —— 严格 RESP 报文交互（发送字节 / 接收原始字节）——")

try:
    s, r = redis_conn(ports["redis"])

    ping_tx = frame("PING")
    s.sendall(ping_tx)
    _, pong_val = take("PING 回复可读")
    ping_raw = r.raw
    print(f"  TX {ping_tx.hex()}  {ping_tx!r}")
    print(f"  RX {ping_raw.hex()}  {ping_raw!r}")
    rcheck("PING 回复原始字节严格等于 +PONG\\r\\n", ping_raw == b"+PONG\r\n",
           f"{ping_raw!r}（解析值 {pong_val!r}）")

    info_tx = frame("INFO")
    s.sendall(info_tx)
    _, info_body = take("INFO 回复可读")
    info_raw = r.raw[len(ping_raw):]
    declared = int(info_raw.split(b"\r\n", 1)[0][1:])
    rcheck("INFO 声明长度 == 实际 body 长度", declared == len(info_body.encode()),
           f"声明={declared} 实际={len(info_body.encode())}")
    rcheck("INFO 含 redis_version:7.0.15", "redis_version:7.0.15" in info_body)

    keys_tx = frame("KEYS", "*")
    s.sendall(keys_tx)
    k_kind, k_val = take("KEYS 回复可读")
    rcheck("KEYS * 是数组且元素数 == 声明", k_kind == "*" and len(k_val) == 6,
           f"{k_kind} n={len(k_val)}")

    get_tx = frame("GET", "deploy:token")
    raw_before = r.raw
    s.sendall(get_tx)
    g_kind, g_val = take("GET 回复可读")
    get_raw = r.raw[len(raw_before):]
    g_decl = int(get_raw.split(b"\r\n", 1)[0][1:])
    print(f"  TX {get_tx.hex()}  {get_tx!r}")
    print(f"  RX {get_raw.hex()}  {get_raw!r}")
    rcheck("GET deploy:token 返回 bulk 且以 rk_ 开头",
           g_kind == "$" and str(g_val).startswith("rk_"), f"{g_kind} {str(g_val)[:16]}…")
    rcheck("GET 的 bulk 长度声明与实际一致", g_decl == len(g_val),
           f"声明={g_decl} 实际={len(g_val)}")

    scan_tx = frame("SCAN", "0")
    raw_before = r.raw
    s.sendall(scan_tx)
    sc_kind, sc_val = take("SCAN 回复可读")
    scan_raw = r.raw[len(raw_before):]
    print(f"  TX {scan_tx.hex()}  {scan_tx!r}")
    print(f"  RX {scan_raw.hex()}  {scan_raw[:60]!r}…")
    # 真 Redis: *2 -> [ 游标(bulk string), 键数组 ]
    ok_scan = (sc_kind == "*" and len(sc_val) == 2
               and sc_val[0][0] == "$" and sc_val[0][1] == "0"
               and sc_val[1][0] == "*" and len(sc_val[1][1]) == 6)
    rcheck("SCAN 结构 = *2 → [bulk 游标 '0', 键数组(6)]", ok_scan,
           f"游标类型={sc_val[0][0] if sc_val else '?'} 头部字节={scan_raw[:12]!r}")
    s.close()
except _StopRedis:
    print("  [跳过] Redis 段剩余步骤（上一条已给出具体错因）")


# 空 inline 行：真 Redis 忽略它、不回包也不断连。服务端若把它当断连信号，
# 就是一处可被指纹识别的差异（`printf '\r\n' | nc host 6379` 立刻分辨真假）。
s, r = redis_conn(ports["redis"])
s.sendall(b"\r\n")
s.sendall(frame("PING"))
try:
    _, v = r.reply()
    ok_blank = v == "PONG"
    detail = f"同一连接仍回 {v!r}"
except (EOFError, ConnectionResetError, socket.timeout) as e:
    ok_blank, detail = False, f"{type(e).__name__}: {e}"
rcheck("空行不断连（真 Redis 行为）", ok_blank, detail)
s.close()

# 旧脚本的真实字节：尾部多一个 CRLF。修好后它也必须活着 ——
# 这既钉住回归，也保证「多发一个空行」不再是我们与真 Redis 的差异。
s, r = redis_conn(ports["redis"])
legacy_tx = b"*1\r\n$4\r\nPING\r\n\r\n"
s.sendall(legacy_tx)
try:
    _, v = r.reply()
    ok_legacy = v == "PONG"
    detail = f"仍回 {v!r}"
except (EOFError, ConnectionResetError, socket.timeout) as e:
    ok_legacy, detail = False, f"{type(e).__name__}: {e}"
rcheck("尾部多 CRLF 的旧字节串不断连", ok_legacy, detail)
s.close()

# 流水线：一次 send 三条，必须按序回三条（RESP 解析器不许串帧）
s, r = redis_conn(ports["redis"])
pipe = frame("PING") + frame("DBSIZE") + frame("GET", "counter:hits")
s.sendall(pipe)
try:
    seq = [r.reply() for _ in range(3)]
    ok_pipe = seq[0][1] == "PONG" and seq[1][1] == "6" and seq[2][1] == "1284119"
    detail = f"{[v for _, v in seq]}"
except Exception as e:
    ok_pipe, detail = False, f"{type(e).__name__}: {e}"
rcheck("流水线三连按序回复、不串帧", ok_pipe, detail)
s.close()

# 未知命令错误帧格式（redis-py 会 parse_error）
s, r = redis_conn(ports["redis"])
s.sendall(frame("FROBNICATE", "x"))
kind, v = r.reply()
rcheck("未知命令回 -ERR 且带命令名", kind == "-" and "unknown command" in v and "FROBNICATE" in v,
       f"{kind}{v}")
s.close()

res["redis"] = all(ok for _, ok, _ in rchecks)
print(f"[Redis] {sum(1 for _, ok, _ in rchecks if ok)}/{len(rchecks)} 项通过")

# ---- ES ----
def http_get(port, path="/"):
    s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(3)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
    s.close(); return data

es = http_get(ports["es"])
es_body = es.split(b"\r\n\r\n", 1)[1]
j = json.loads(es_body)
print(f"\n[ES] name={j['name']} cluster={j['cluster_name']} ver={j['version']['number']}")
print(f"[ES] X-elastic-product 头: {'✅' if b'X-elastic-product' in es else '❌'}")
res["es"] = j["cluster_name"] == "fin-archive-cluster" and b"X-elastic-product" in es

# ---- SMTP ----
s = socket.create_connection(("127.0.0.1", ports["smtp"]), 3); s.settimeout(3)
greet = s.recv(256)
s.sendall(b"EHLO probe\r\n"); time.sleep(0.2)
ehlo = s.recv(1024); s.close()
print(f"\n[SMTP] {greet.strip()!r}")
print(f"[SMTP EHLO] {ehlo.decode('latin-1').strip()[:120]!r}")
res["smtp"] = b"220" in greet and b"250-" in ehlo

farm.stop()
print("\n" + "=" * 54)
for k, v in res.items():
    print(f"  {k:6} {'✅' if v else '❌'}")
print(f"协议自测 {sum(res.values())}/{len(res)} 通过")
print(f"命中记录 {len(farm.hits)} 条: {[h['proto']+':'+h['detail'] for h in farm.hits[:8]]}")
# 机器可判的退出码：全绿才 0。以前只打印不给码，CI 里「看着绿」不等于绿。
sys.exit(0 if all(res.values()) else 1)
