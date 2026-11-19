"""Redis handler 单步调试：把服务端异常打出来"""
import os, socket, sys, threading, time, traceback
sys.path.insert(0, os.path.expanduser("~/tools/agent-honeypot"))
import honey_proto
from honey_world import World

# 把 _guard 的静默吞异常改成打印 traceback
_orig = honey_proto.ProtoFarm._guard
def _loud(self, handler, conn, addr):
    try:
        conn.settimeout(8)
        if handler:
            handler(conn, addr)
    except Exception:
        traceback.print_exc()
    finally:
        try: conn.close()
        except Exception: pass
honey_proto.ProtoFarm._guard = _loud

w = World(seed=3)
farm = honey_proto.ProtoFarm(w, "selftest-secret", bind="127.0.0.1")
farm.start()
p = farm.ports["redis"]
print("redis port", p)

s = socket.create_connection(("127.0.0.1", p), 3); s.settimeout(3)
f = s.makefile("rwb")
for cmd in ["PING", "INFO"]:
    n = len(cmd.split())
    f.write(b"*" + str(n).encode() + b"\r\n" +
            b"".join(b"$" + str(len(x)).encode() + b"\r\n" + x.encode() + b"\r\n"
                     for x in cmd.split()) + b"\r\n")
    f.flush(); time.sleep(0.2)
    try:
        hdr = f.readline()
        print(f"[{cmd}] hdr={hdr!r}")
        if hdr[:1] == b"$":
            ln = int(hdr[1:].strip()); body = f.read(ln); f.read(2)
            print(f"  body[{ln}]={body[:80]!r}")
    except Exception as e:
        print(f"[{cmd}] 客户端异常 {type(e).__name__}: {e}")
        break
s.close()
time.sleep(0.3)
print("hits:", farm.hits)
farm.stop()
