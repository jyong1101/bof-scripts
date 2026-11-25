#!/usr/bin/env python3
"""Authorised coursework; localhost only.

A TCP proxy that adds network delay, so the toolkit can be tested the way the exam host
behaves rather than the way localhost does. Every clone here answers in microseconds; the
professor's practice host was a cloud machine about 230 ms away, round trip. A read
timeout that is generous on loopback can be shorter than one network hop.

  python3 lagproxy.py --listen 40001 --to 40000 --delay 0.15      # 150 ms EACH way
  python3 lagproxy.py --listen 40001 --to 40000 --delay 0.15 --jitter 0.05 --chunk 7

--chunk N additionally delivers data N bytes at a time with a small gap, the way a slow
link fragments a reply: a tool that treats "the first recv" as "the whole message" breaks.
Binds 127.0.0.1 only and forwards to 127.0.0.1 only.
"""
import argparse, random, socket, threading, time

HOST = "127.0.0.1"


def pump(src, dst, delay, jitter, chunk):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            time.sleep(max(0.0, delay + random.uniform(-jitter, jitter)))
            if chunk:
                for i in range(0, len(data), chunk):
                    dst.sendall(data[i:i + chunk])
                    time.sleep(0.004)
            else:
                dst.sendall(data)
    except OSError:
        pass
    finally:
        # propagate the close after the same delay, like a real FIN would arrive late
        time.sleep(delay)
        for s in (dst, src):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def handle(c, to, delay, jitter, chunk):
    try:
        time.sleep(delay)                              # the SYN's own trip
        u = socket.create_connection((HOST, to), timeout=5)
    except OSError:
        c.close()
        return
    threading.Thread(target=pump, args=(c, u, delay, jitter, 0), daemon=True).start()
    threading.Thread(target=pump, args=(u, c, delay, jitter, chunk), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description="local TCP proxy that adds latency")
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--to", type=int, required=True)
    ap.add_argument("--delay", type=float, default=0.15, help="seconds added in EACH direction")
    ap.add_argument("--jitter", type=float, default=0.0)
    ap.add_argument("--chunk", type=int, default=0, help="deliver replies N bytes at a time")
    a = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    import errno
    deadline = time.time() + 75
    while True:                                        # same TIME_WAIT wait-out as server.py
        try:
            srv.bind((HOST, a.listen))
            break
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE or time.time() > deadline:
                raise
            time.sleep(0.5)
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, a.to, a.delay, a.jitter, a.chunk), daemon=True).start()


if __name__ == "__main__":
    main()
