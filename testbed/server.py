#!/usr/bin/env python3
"""Stdlib-only TCP wrapper that exposes a local challenge binary on 127.0.0.1.

One child process per connection. Socket bytes -> child stdin; child
stdout+stderr -> socket. The child runs with cwd=sandbox/ so that
flags/f.txt and flags/t.txt resolve.

SAFETY: binds 127.0.0.1 only. No outbound connections. Authorised LOCAL
practice use only.

Examples:
  python3 server.py ./buff32 --port 15055
  python3 server.py ./form32 --port 3312
  python3 server.py ./genie32 --port 4412
  python3 server.py ./simple_strcmp32 --port 15056
  python3 server.py ./buff32 --port 15055 --no-aslr   # setarch -R child
"""
import argparse
import os
import shlex
import socket
import subprocess
import sys
import threading

HOST = "127.0.0.1"  # hard-locked to loopback; do not change.


def pump(src_read, dst_write):
    """Copy bytes from a readable fd/file to a writable one until EOF."""
    try:
        while True:
            data = src_read(4096)
            if not data:
                break
            dst_write(data)
    except (OSError, ValueError):
        pass


# Children still running, so they can be stopped when this server is. Without this a child
# that never exits on its own (shellcode that lands in a loop) outlived the server as an
# orphan at 100% CPU: three of them ran for 3, 7 and 22 hours and slowed everything else.
CHILDREN = set()
CHILDREN_LOCK = threading.Lock()
LINGER = 10.0        # seconds a child may keep running after its client has gone


def stop_children(*_a):
    with CHILDREN_LOCK:
        procs = list(CHILDREN)
    for p in procs:
        try:
            p.kill()
        except OSError:
            pass
    if _a:                       # called as a signal handler: finish exiting
        os._exit(0)


def handle(conn, addr, cmd, cwd):
    conn.settimeout(None)
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
    except OSError as exc:
        try:
            conn.sendall(f"[server] cannot exec {cmd!r}: {exc}\n".encode())
        finally:
            conn.close()
        return

    def sock_to_child():
        pump(conn.recv, proc.stdin.write)
        try:
            proc.stdin.close()
        except OSError:
            pass

    def child_to_sock():
        pump(proc.stdout.read1 if hasattr(proc.stdout, "read1") else proc.stdout.read,
             conn.sendall)

    t_in = threading.Thread(target=sock_to_child, daemon=True)
    t_out = threading.Thread(target=child_to_sock, daemon=True)
    t_in.start()
    t_out.start()
    with CHILDREN_LOCK:
        CHILDREN.add(proc)

    # Wait for the child - but once the client has gone, only LINGER seconds more. A real
    # service would be killed by its supervisor; here nothing else would ever do it.
    import time as _t
    gone_at = None
    while proc.poll() is None:
        if gone_at is None and not t_in.is_alive():
            gone_at = _t.time()
        if gone_at is not None and _t.time() - gone_at > LINGER:
            try:
                proc.kill()
            except OSError:
                pass
            break
        _t.sleep(0.05)
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass
    with CHILDREN_LOCK:
        CHILDREN.discard(proc)
    t_out.join(timeout=1.0)
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    conn.close()


def main():
    ap = argparse.ArgumentParser(description="Local-only TCP wrapper for a challenge binary")
    ap.add_argument("binary", help="path to the challenge binary (e.g. ./buff32)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cwd", default=os.path.dirname(os.path.abspath(__file__)),
                    help="working dir for the child (default: this sandbox/ dir)")
    ap.add_argument("--no-aslr", action="store_true",
                    help="wrap the child in `setarch -R` to disable ASLR")
    ap.add_argument("--args", default="", help="extra argv for the child (shell-split)")
    args = ap.parse_args()

    binpath = args.binary
    if os.path.sep in binpath or binpath.startswith("."):
        binpath = os.path.abspath(binpath)
    if not os.path.exists(binpath):
        sys.exit(f"[server] binary not found: {args.binary}")

    cmd = [binpath] + shlex.split(args.args)
    if args.no_aslr:
        cmd = ["setarch", "-R"] + cmd

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # The port may be busy for up to a minute for a reason that has nothing to do with
    # another server: Linux hands out 32768-60999 as CLIENT source ports, and a port a
    # client just used sits in TIME_WAIT for 60s, during which a listener cannot bind it
    # even with SO_REUSEADDR. A test suite that opens thousands of connections and uses
    # fixed ports in that range trips over its own traffic ("port N never came up", on a
    # different row every run). Wait it out instead of dying.
    import errno, time
    deadline = time.time() + 75
    while True:
        try:
            srv.bind((HOST, args.port))        # 127.0.0.1 only
            break
        except OSError as exc:
            if exc.errno != errno.EADDRINUSE or time.time() > deadline:
                raise
            time.sleep(0.5)
    srv.listen(16)
    import signal
    signal.signal(signal.SIGTERM, stop_children)      # `kill PID` is how the harness stops us
    print(f"[server] {binpath} on {HOST}:{args.port} cwd={args.cwd} "
          f"aslr={'off' if args.no_aslr else 'on'} (Ctrl-C to stop)")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, cmd, args.cwd),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[server] shutting down")
    finally:
        srv.close()
        stop_children()


if __name__ == "__main__":
    main()
