#!/usr/bin/env python3
"""listen backlog 审计：证明 honeypot 的 backlog=5 会在并发突发下丢连接。

背景
────
`socketserver.TCPServer.request_queue_size` 默认值是 **5**，`ThreadingHTTPServer`
继承这个默认值。当并发连接数超过 accept 速度时，内核的 listen 队列装满，后续
SYN 直接被 RST —— 客户端看到的是连接被拒，服务端连一个请求都没收到。

对蜜罐来说这不是普通的丢包：每个被拒的连接都是一次没被记录的探测。攻击 agent
发 16 个请求丢掉 16 个，账本上就是一条空记录，判定从「深度交互」降级成
「浅层扫过」，整个会话的证据链断掉。

测法
────
对照组设计，同一台机器同一时刻、同一 handler、同一并发数，只改 backlog：

  A 组：backlog = 5    （http.server 默认值，修复前）
  B 组：backlog = 128  （HoneypotHTTPServer，修复后）

客户端用 threading.Barrier 让所有线程同一瞬间发起 connect，制造真正的突发，
而不是被 Python 线程启动开销摊平的伪并发。

判定
────
B 组的连接失败数必须显著低于 A 组。若两组都 0 失败，说明本机内核/并发数没
压出队列溢出，本轮结论无效（不是通过）——脚本会明确报 INCONCLUSIVE。

用法
────
    python3 _audit_backlog.py            # 默认 100 并发 × 3 轮
    python3 _audit_backlog.py 200 5      # 200 并发 × 5 轮

退出码：0 = 修复有效；1 = 修复无效或结论无效。
"""

from __future__ import annotations

import socket
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import honey_server


class _SlowHandler(BaseHTTPRequestHandler):
    """每次请求故意占住工作线程一会儿，放大 listen 队列的堆积。"""

    HOLD = 0.05

    def do_GET(self) -> None:  # noqa: N802
        time.sleep(self.HOLD)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:  # 静音，压测不该刷屏
        pass


def _server_class(backlog: int):
    """backlog 只在 server_bind() → listen(backlog) 时生效，必须类属性。"""

    class _S(ThreadingHTTPServer):
        request_queue_size = backlog
        daemon_threads = True

    return _S


def _burst(port: int, n: int) -> tuple[int, float]:
    """n 个线程同一瞬间 connect，返回 (失败数, 成功连接的耗时总和秒)。"""
    barrier = threading.Barrier(n)
    failures: list[int] = []
    latencies: list[float] = []
    lock = threading.Lock()

    def one() -> None:
        try:
            barrier.wait()
            t0 = time.perf_counter()
            s = socket.create_connection(("127.0.0.1", port), timeout=5.0)
            s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            s.recv(64)
            s.close()
            with lock:
                latencies.append(time.perf_counter() - t0)
        except Exception:
            with lock:
                failures.append(1)

    threads = [threading.Thread(target=one, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    return len(failures), sum(latencies)


def _trial(backlog: int, n: int, rounds: int) -> list[int]:
    out: list[int] = []
    for r in range(rounds):
        srv = _server_class(backlog)(("127.0.0.1", 0), _SlowHandler)
        port = srv.server_address[1]
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            fails, _ = _burst(port, n)
            out.append(fails)
            print(f"    backlog={backlog:<4} 第 {r + 1} 轮：失败 {fails}/{n}")
        finally:
            srv.shutdown()
            srv.server_close()
        time.sleep(0.15)  # 让上一轮的 TIME_WAIT 散掉，别串轮
    return out


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 3

    # 确认被测代码真的改了默认值
    real_backlog = honey_server.HoneypotHTTPServer.request_queue_size
    is_subclass = issubclass(honey_server.HoneypotHTTPServer, ThreadingHTTPServer)
    default_backlog = threading.Thread  # 占位，下面直接用 5 做对照
    print("== 被测对象 ==")
    print(f"  honey_server.HoneypotHTTPServer.request_queue_size = {real_backlog}")
    print(f"  issubclass(ThreadingHTTPServer) = {is_subclass}")
    print(f"  对照组（修复前默认值） = {ThreadingHTTPServer.request_queue_size}")
    print()

    if real_backlog <= ThreadingHTTPServer.request_queue_size:
        print("FAIL: 修复后的 backlog 没有大于 http.server 默认值，改动没生效。")
        return 1

    print(f"== A 组：修复前（backlog={ThreadingHTTPServer.request_queue_size}）==")
    a = _trial(ThreadingHTTPServer.request_queue_size, n, rounds)
    print()
    print(f"== B 组：修复后（backlog={real_backlog}）==")
    b = _trial(real_backlog, n, rounds)
    print()

    a_total, b_total = sum(a), sum(b)
    a_rate = a_total / (n * rounds) * 100
    b_rate = b_total / (n * rounds) * 100

    print("== 结论 ==")
    print(f"  A 组失败：{a_total}/{n * rounds} = {a_rate:.2f}%   逐轮 {a}")
    print(f"  B 组失败：{b_total}/{n * rounds} = {b_rate:.2f}%   逐轮 {b}")
    print(f"  中位数：A={statistics.median(a)}  B={statistics.median(b)}")

    if a_total == 0 and b_total == 0:
        print()
        print("  INCONCLUSIVE：两组都没丢连接——本机 backlog=5 在这个并发数下没压溢出。")
        print("  提高并发数重跑（例如 python3 _audit_backlog.py 300 3）再下结论。")
        return 1

    if b_total < a_total:
        print()
        print(f"  PASS：修复后丢连接从 {a_rate:.2f}% 降到 {b_rate:.2f}%"
              f"（减少 {a_total - b_total} 条 / {n * rounds}）。")
        return 0

    print()
    print("  FAIL：修复后没有改善，backlog 不是丢连接的根因。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
