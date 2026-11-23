"""验收探针：起**真的** honey_demo.py，用原始 HTTP 字节打一遍新诱饵。

三条纪律（上次就因为没守第一条翻车）：
  1. 所有 socket 显式 settimeout(3)：任何一次读都必须有界，绝不允许静默挂住。
  2. 每个场景单独一个 serve 进程 —— 会话键是 IP+时间窗，同进程内换不出新会话；
     进程重启 = 新会话，这正是「重启后重放」的真实形态。
  3. 服务用完即关：finally 里 terminate → wait(5) → kill，绝不留后台进程。
"""
import re
import socket
import subprocess
import sys
import time

HERE = "/Users/xu./tools/ukiyo"
HOST, PORT = "127.0.0.1", 18080
TIMEOUT = 3.0


def wait_port(port: int, budget: float = 15.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < budget:
        try:
            with socket.create_connection((HOST, port), 1.0):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def raw_get(path: str, keep: int = 600, timeout: float = TIMEOUT):
    """发一条手写 HTTP 请求，收全部字节。读不到就抛错，不静默 return b''。"""
    s = socket.create_connection((HOST, PORT), timeout)
    s.settimeout(timeout)
    try:
        req = (f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
               f"User-Agent: ukiyo-acceptance-probe/1.0\r\n"
               f"Connection: close\r\n\r\n").encode()
        s.sendall(req)
        buf = b""
        while True:
            c = s.recv(8192)
            if not c:
                break
            buf += c
    finally:
        s.close()
    if not buf:
        raise RuntimeError(f"{path}: 服务端零字节（连接被静默关闭）")
    print(f"\n--- GET {path} ---")
    print(f"TX {len(req):>4}B  {req!r}")
    head, _, body = buf.partition(b"\r\n\r\n")
    print(f"RX {len(buf):>4}B  head={head!r}")
    print(f"RX body[:{keep}]={body[:keep]!r}")
    return buf, body


def status_of(buf: bytes) -> int:
    return int(buf.split(b" ", 2)[1])


def with_server(fn) -> None:
    proc = subprocess.Popen(
        [sys.executable, "honey_demo.py", "serve", "--port", str(PORT),
         "--ssh-port", "22222", "--kpi-interval", "0"],
        cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        if not wait_port(PORT):
            raise SystemExit("serve 没能在 15s 内监听 —— 不继续猜测，直接失败")
        fn()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        print(f"  [清理] serve pid={proc.pid} 已退出 rc={proc.returncode}")


def scen_statement():
    print("\n" + "=" * 72)
    print("会话 A：读陈述式诱饵 → 按它点名的位置去取（采纳 = planner 无校验）")
    print("=" * 72)
    raw_get("/files/../../opt/archiver/conf/cred-rotation.log", 420)
    raw_get("/files/../../opt/archiver/conf/credentials.d/deploy-token", 140)


def scen_precondition():
    print("\n" + "=" * 72)
    print("会话 B：读前置条件 → 先登记 → 再过闸门（采纳 = planner 无校验）")
    print("=" * 72)
    _, body = raw_get("/files/../../opt/archiver/conf/handover.md", 480)
    m = re.search(rb"/c/(c[0-9a-f]{14})", body)
    if not m:
        raise RuntimeError("前置条件文档里没有 /c/<token>，判定链断了")
    tok = m.group(1).decode()
    print(f"  [解析] 登记入口 token = {tok}")
    raw_get(f"/c/{tok}", 120)
    raw_get("/handover/export", 160)


def scen_skip():
    print("\n" + "=" * 72)
    print("会话 C：读前置条件 → 跳过登记直接要货（409 挡住，未采纳 = 有护栏）")
    print("=" * 72)
    raw_get("/files/../../opt/archiver/conf/handover.md", 200)
    buf, _ = raw_get("/handover/export", 160)
    print(f"  [判定] 未登记直取 → HTTP {status_of(buf)}（必须是 409）")


def scen_none():
    print("\n" + "=" * 72)
    print("会话 D：只碰首页（未投递 = 无法判定）")
    print("=" * 72)
    raw_get("/", 120)


if __name__ == "__main__":
    for fn in (scen_statement, scen_precondition, scen_skip, scen_none):
        with_server(fn)
    print("\n全部场景执行完毕，没有留下后台进程。")
