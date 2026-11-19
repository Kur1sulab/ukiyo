"""协议层自测：用真客户端 + nmap -sV 判定是否被识别为真服务"""
import json, os, socket, struct, subprocess, sys, time
sys.path.insert(0, os.path.expanduser("~/tools/agent-honeypot"))
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

# ---- Redis: RESP 全套 ----
def resp(port, *cmds):
    s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(3)
    f = s.makefile("rwb"); out = []
    for c in cmds:
        f.write(b"*" + str(len(c.split())).encode() + b"\r\n" +
                b"".join(b"$" + str(len(x)).encode() + b"\r\n" + x.encode() + b"\r\n"
                         for x in c.split()) + b"\r\n")
        f.flush()
        time.sleep(0.12)
        # 按 RESP 类型头精确读一条回复（不能用 read(4096)——会等满 4096 字节）
        hdr = f.readline()
        if hdr[:1] in (b"+", b"-", b":"):
            out.append(hdr.decode("latin-1", "replace"))
        elif hdr[:1] == b"$":
            n = int(hdr[1:].strip())
            out.append(f.read(n).decode("latin-1", "replace") if n >= 0 else "")
            f.read(2)
        elif hdr[:1] == b"*":
            n = int(hdr[1:].strip())
            buf = []
            for _ in range(max(n, 0)):
                h = f.readline()
                if h[:1] == b"$":
                    ln = int(h[1:].strip())
                    buf.append(f.read(ln).decode("latin-1", "replace") if ln >= 0 else "")
                    f.read(2)
                else:
                    buf.append(h.strip().decode("latin-1", "replace"))
            out.append("\n".join(buf))
        else:
            out.append(hdr.decode("latin-1", "replace"))
    s.close(); return out

pong, info, keys, tok = resp(ports["redis"], "PING", "INFO", "KEYS *", "GET deploy:token")
print(f"\n[Redis PING] {pong.strip()!r}")
print(f"[Redis INFO] 前两行: {[l for l in info.splitlines() if l][:2]}")
print(f"[Redis KEYS] {keys.strip()[:120]!r}")
print(f"[Redis GET deploy:token] {tok.split(chr(13)+chr(10))[-2][:40] if tok else ''!r}")
res["redis"] = "+PONG" in pong and "redis_version:7.0.15" in info and "deploy:token" in keys and tok.startswith("$")

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
