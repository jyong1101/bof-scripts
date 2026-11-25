#!/usr/bin/env python3
"""Authorised coursework. Reads what the PAPER says and turns it into facts.

A challenge can keep a value off the wire - printed on the question paper, in a PDF, on
the whiteboard - so that a prepared script has nothing to read. This module is the other
half of that: type or paste the paper's words into a .txt file and it picks out what the
exploit tools need. It is pattern matching on numbers and the words next to them, not
understanding; that is why `describe()` shows what was read BEFORE anything is sent.

  python3 notes.py paper.txt          # show what it reads from a file
  echo "buffer is 64 bytes, win at 0x401186" | python3 notes.py -

A fact is {"kind", "value", "label", "line"}:
  offset   distance to the return address, stated outright      "offset is 76"
  size     a buffer size; the offset is this plus padding        "char buf[64]", "64 bytes"
  address  somewhere in the program or on the stack              "win() is at 0x401186"
  number   any other value: a guard, a key, a win() argument     "access code: 0x1337c0de"
  text     a word to type: a password, a username, a string     "password is hunter2"

Arithmetic is evaluated ("0x40 + 12", "1337 xor 0x55") and the RESULT is a fact too, placed
first, because a paper that makes you calculate wants the result.
"""
import json, os, re, sys

NUM = r"(?:0[xX][0-9a-fA-F]+|\d+)"
OPS = {"+": lambda a, b: a + b, "-": lambda a, b: a - b, "*": lambda a, b: a * b,
       "x": lambda a, b: a * b, "^": lambda a, b: a ^ b, "xor": lambda a, b: a ^ b,
       "&": lambda a, b: a & b, "and": lambda a, b: a & b, "|": lambda a, b: a | b,
       "or": lambda a, b: a | b, "plus": lambda a, b: a + b, "minus": lambda a, b: a - b,
       "times": lambda a, b: a * b}
OFFSET_WORDS = r"(?:offset|padding|pad|distance|bytes?\s+(?:to|until|before)\s+(?:the\s+)?(?:saved\s+)?(?:return|ret|eip|rip))"
SIZE_WORDS = r"(?:buffer|buf|array|char\s+\w+|size|long|length|holds?|stores?)"
VALUE_WORDS = r"(?:code|key|value|magic|secret|pin|number|token|argument|arg|param|target|guard|answer|equal(?:s)?|must\s+be|set\s+to|should\s+be)"
ADDR_WORDS = r"(?:address|addr|located|at|jump|return\s+to|win|function|flag\s*\(|shell\s*\(|buffer\s+(?:is\s+)?at)"
TEXT_WORDS = r"(?:password|passwd|pass|passphrase|username|user|login|name|word|string|phrase|secret|key|code)"
STOP = {"is", "are", "the", "a", "an", "of", "to", "at", "in", "and", "or", "your", "you", "it", "that", "this",
        "be", "must", "should", "equal", "equals", "set", "with", "for", "use", "as", "bytes", "byte", "hex"}


def _n(tok):
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok)


def _is_addr(v):
    """Looks like a place in memory rather than a quantity: program text/data, a PIE or
    libc mapping, or the stack. Typical ranges, because the paper gives no binary."""
    return (0x08040000 <= v <= 0x080FFFFF or 0x00400000 <= v <= 0x004FFFFF
            or 0x550000000000 <= v <= 0x56FFFFFFFFFF or 0x56000000 <= v <= 0x57FFFFFF
            or 0xF7000000 <= v <= 0xFFFFFFFF or 0x7F0000000000 <= v <= 0x7FFFFFFFFFFF)


SHOWN = {}


_UNITS = {w: i for i, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve "
                                   "thirteen fourteen fifteen sixteen seventeen eighteen nineteen".split())}
_TENS = {w: 10 * (i + 2) for i, w in enumerate("twenty thirty forty fifty sixty seventy eighty ninety".split())}
_NUMWORD = r"(?:%s)" % "|".join(sorted(list(_UNITS) + list(_TENS) + ["hundred", "thousand"], key=len, reverse=True))


def _words_to_number(phrase):
    total = cur = 0
    for w in re.findall(r"[a-z]+", phrase.lower()):
        if w == "and":
            continue
        if w in _UNITS:
            cur += _UNITS[w]
        elif w in _TENS:
            cur += _TENS[w]
        elif w == "hundred":
            cur = max(cur, 1) * 100
        elif w == "thousand":
            total += max(cur, 1) * 1000
            cur = 0
    return total + cur


def normalise(line):
    """Rewrite other spellings into the plain form parse() reads. Each rule exists because
    a sentence written that way was misread; none of them guesses at meaning."""
    out = line
    # `#define KEY 0x1337` -> "KEY = 0x1337"
    out = re.sub(r"#\s*define\s+(\w+)\s+(\S+)", r"\1 = \2", out)
    # '\xef\xbe\xad\xde' -> the little-endian value those bytes are, 0xdeadbeef
    def _bytes(m):
        bs = bytes(int(x, 16) for x in re.findall(r"\\x([0-9a-fA-F]{2})", m.group(0)))
        return hex(int.from_bytes(bs, "little"))
    out = re.sub(r"(?:\\x[0-9a-fA-F]{2}){2,8}", _bytes, out)
    # 0b1010011 -> 0x53 ;  401186h -> 0x401186
    out = re.sub(r"\b0[bB]([01]+)\b", lambda m: hex(int(m.group(1), 2)), out)
    out = re.sub(r"\b([0-9][0-9a-fA-F]{3,15})[hH]\b", r"0x\1", out)
    # bare hex with no prefix: only when it cannot be an English word or a plain count -
    # 6+ hex digits containing BOTH a digit and a letter, or 8 digits starting with 0
    # (080491f6, 08049216). A pure-letter run (deadbeef) only right after a value word,
    # so "dead", "beef", "cafe", "face", "add" in a sentence stay words.
    def _bare(m):
        t = m.group(0)
        return "0x" + t
    out = re.sub(r"(?<![\w.])(?=[0-9a-fA-F]*[0-9])(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{6,16}(?![\w])", _bare, out)
    out = re.sub(r"(?<![\w.])0[0-9]{7}(?![\w])", _bare, out)
    out = re.sub(r"(\b" + VALUE_WORDS + r"\b\W*(?:is|=|:|of|to)?\W*)([a-fA-F]{8}|[a-fA-F]{16})\b",
                 lambda m: m.group(1) + "0x" + m.group(2), out, flags=re.I)
    # "'A' * 76", "A*76", "76 A's", "76 x 'A'" -> "76 bytes of padding"
    out = re.sub(r"['\"]?\b[A-Za-z]\b['\"]?\s*\*\s*(" + NUM + r")", r"\1 bytes of padding", out)
    out = re.sub(r"(" + NUM + r")\s*(?:x\s*|\*\s*)?['\"]?\b[A-Z]\b['\"]?'?s\b", r"\1 bytes of padding", out)
    # sixty-four -> 64 (whole runs of number words, so "one hundred and twenty eight" is 128)
    def _spelled(m):
        return str(_words_to_number(m.group(0)))
    out = re.sub(r"\b" + _NUMWORD + r"(?:[\s-]+(?:and[\s-]+)?" + _NUMWORD + r")*\b", _spelled, out, flags=re.I)
    # "64 characters", "32 chars" are bytes
    out = re.sub(r"\b(char(?:acter)?s?)\b(?!\s*\w*\[)(?!\s+\w+\s*\[)", lambda m: "bytes" if not m.group(1).lower() == "char" else m.group(0), out, flags=re.I)
    out = re.sub(r"(" + NUM + r")\s*-?\s*character\b", r"\1 bytes", out, flags=re.I)
    return out


def parse(text):
    facts, seen = [], set()
    # A value on the line AFTER its label ("The offset is" / "76") is one statement; and
    # "1,024" is one number, not 1 and 024. Both were misread before they were merely missed.
    text = re.sub(r"(\b(?:is|are|at|to|equals?|of)\b\s*[:=]?|[:=])[ \t]*\r?\n[ \t]*(?=\S)", r"\1 ", text)
    text = re.sub(r"(?<![\w.])(\d{1,3})((?:,\d{3})+)(?![\w,])", lambda m: m.group(1) + m.group(2).replace(",", ""), text)

    def add(kind, value, label, line, front=False):
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        f = {"kind": kind, "value": value, "label": label.strip()[:40], "line": line.strip()[:120]}
        f["line"] = SHOWN.get("line", f["line"])
        facts.insert(0, f) if front else facts.append(f)

    for raw in text.splitlines():
        line = raw.strip()
        if not line or (line.startswith("#") and not re.match(r"#\s*define", line)):
            continue
        SHOWN["line"] = line[:120]          # what the user WROTE, for "I read: ... <- "
        line = normalise(line)
        low = line.lower()
        used = set()                                    # spans already given a meaning

        # --- arithmetic: "0x40 + 12", "1337 xor 0x55", "64 plus 12 bytes"
        # (a bracket may sit between a number and the operator: "the size (64) times 2")
        for m in re.finditer(r"(%s)\)?\s*(\+|-|\*|\^|&|\||\bxor\b|\band\b|\bor\b|\bplus\b|\bminus\b|\btimes\b|\bx\b)\s*\(?(%s)" % (NUM, NUM),
                             line, re.I):
            a, op, b = _n(m.group(1)), m.group(2).lower(), _n(m.group(3))
            try:
                r = OPS[op](a, b)
            except Exception:
                continue
            if r < 0:
                continue
            before = low[max(0, m.start() - 40):m.start()]
            kind = "offset" if re.search(OFFSET_WORDS, before) else \
                   "size" if re.search(SIZE_WORDS + r"\W*(?:is|=|:|of)?\W*$", before) else \
                   "address" if _is_addr(r) else "number"
            add(kind, r, f"computed: {m.group(0)} = {hex(r)}", line, front=True)
            if kind in ("size", "offset"):
                # "the secret is the buffer size (64) times 2": the words nearby say
                # "size", the sentence means a VALUE. Keep both readings; nothing is lost.
                add("number", r, f"computed: {m.group(0)} = {hex(r)}", line, front=True)

        # --- "offset is 76", "padding of 0x48"
        for m in re.finditer(OFFSET_WORDS + r"\D{0,40}?(" + NUM + r")", low):
            if _n(m.group(1)) > 8192 or _n(m.group(1)) < 4 or _is_addr(_n(m.group(1))):
                continue                    # "padding followed by the address 0x401196";
                                            # "...the padding... One face of it" is not offset 1
            add("offset", _n(m.group(1)), "offset", line)
            used.add(m.span(1))
        # --- "send 72 bytes of padding": that count IS the distance, not a buffer size
        for m in re.finditer(r"(" + NUM + r")\s*bytes?\s+of\s+(?:padding|junk|filler|garbage|a'?s\b)", low):
            add("offset", _n(m.group(1)), "bytes of padding", line)
            used.add(m.span(1))
        # --- "char buf[64]", "64 bytes", "buffer is 64", "64-byte buffer"
        for pat in (r"\[\s*(" + NUM + r")\s*\]", r"(" + NUM + r")\s*-?\s*bytes?\b",
                    SIZE_WORDS + r"\D{0,16}?(" + NUM + r")\b(?!\s*(?:\+|-|\*|x\b))"):
            for m in re.finditer(pat, low):
                if m.span(1) in used:
                    continue
                v = _n(m.group(1))
                if 4 <= v <= 4096 and not _is_addr(v):
                    add("size", v, "buffer size", line)
                    used.add(m.span(1))

        # --- every remaining number: an address if it looks like one, else a value
        # (a full stop after the number ends the sentence; only ".5" would make it a decimal)
        for m in re.finditer(r"(?<![\w.])(" + NUM + r")(?!\w|\.\d|\s*-?\s*bytes?\b)", line):
            if m.span(1) in used:
                continue
            v = _n(m.group(1))
            before = low[max(0, m.start() - 36):m.start()]
            words = [w for w in re.findall(r"[a-z_()]+", before) if w not in STOP]
            label = " ".join(words[-2:]) or "number"
            if m.group(1).lower().startswith("0x") and _is_addr(v):
                add("address", v, label, line)
            elif re.search(ADDR_WORDS + r"\W*(?:is|=|:|at)?\W*$", before) and _is_addr(v):
                add("address", v, label, line)
            else:
                # one- and two-digit decimals are usually prose ("question 3", "2 marks")
                # unless a value word introduces them
                if re.search(r"\b(?:port|question|q|marks?|page|room|section|week)\W*$", before):
                    continue                # "running on port 5002", "question 6" are not values
                small = not m.group(1).lower().startswith("0x") and v < 100
                if small and not re.search(VALUE_WORDS + r"\W*(?:is|=|:|of|to)?\W*$", before):
                    continue
                add("number", v, label, line)

        # --- words to type: quoted, or after "password is ..."
        for m in re.finditer(r"[\"'`“‘]([^\"'`”’]{2,40})[\"'`”’]", line):
            add("text", m.group(1), "quoted", line)
        for m in re.finditer(r"\b(" + TEXT_WORDS + r")\b\s*(?:is|=|:|\bof\b)\s*[\"'`]?([A-Za-z0-9_@#$%!.\-]{3,40})", line, re.I):
            w = m.group(2).rstrip(".,;")
            if re.fullmatch(NUM, w) or w.lower() in STOP:
                continue
            add("text", w, m.group(1).lower(), line)

    # value-like numbers before unlabelled ones; nothing is dropped
    rank = lambda f: 0 if f["label"].startswith("computed") else \
        1 if re.search(VALUE_WORDS, f["label"]) else 2
    order = {"offset": 0, "size": 1, "address": 2, "number": 3, "text": 4}
    return sorted(facts, key=lambda f: (order[f["kind"]], rank(f)))


def offsets_from(facts, bits=None):
    """Offsets worth trying, best first. A stated offset is used as given. A buffer SIZE is
    not the offset: the saved frame pointer (4 or 8 bytes) and any alignment padding sit
    between the buffer and the return address, so a size becomes a short list."""
    out = [f["value"] for f in facts if f["kind"] == "offset"]
    for f in facts:
        if f["kind"] != "size":
            continue
        n = f["value"]
        steps = ([4, 8, 12, 16, 20, 24, 28, 0] if bits == 32 else
                 [8, 16, 24, 32, 0] if bits == 64 else [4, 8, 12, 16, 20, 24, 28, 32, 0])
        for d in steps:
            if n + d not in out:
                out.append(n + d)
    # Second tier: ANOTHER local variable between the buffer and the return address (a
    # 32-byte name beside a 200-byte message puts the distance at size+48). Still anchored
    # on the stated size - carrying on upward from it beats restarting a sweep at 8.
    for f in facts:
        if f["kind"] == "size":
            for d in range(36, 100, 4):
                if f["value"] + d not in out:
                    out.append(f["value"] + d)
    return out


def describe(facts):
    """Plain-language list of what was read, for the user to check before anything runs."""
    if not facts:
        return ["  (nothing usable found in the notes - running as if there were none)"]
    how = {"offset": "distance to the return address - used as given",
           "size": "a buffer size - the return address is a few bytes past it; trying size+4, +8, +12 ...",
           "address": "a code address - somewhere to return to (win), or a jmp esp to put shellcode behind",
           "number": "a value - tried as the guard value, win() argument and value to write",
           "text": "a word to type - tried as a login and as a compared string"}
    out = []
    for f in facts:
        v = f["value"]
        if f["kind"] == "address" and (0xF7000000 <= v <= 0xFFFFFFFF or v >= 0x7F0000000000):
            out.append(f"  {'address':8} {'0x%x' % v:28} <- \"{f['line'][:60]}\"")
            out.append(f"  {'':8} a STACK address (where a buffer or a saved value lives) - changes every run; "
                       f"not a place to return to")
            continue
        shown = (f"{v} (0x{v:x})" if f["kind"] in ("offset", "size") else
                 f"0x{v:x}" if f["kind"] == "address" else
                 f"{v} (0x{v:x})" if f["kind"] == "number" else repr(v))
        out.append(f"  {f['kind']:8} {shown:28} <- \"{f['line'][:60]}\"")
        out.append(f"  {'':8} {how[f['kind']]}")
    return out


def load():
    """Facts handed down by solve.py / go.py through the environment (child tools call this)."""
    try:
        return json.loads(os.environ.get("CTF_HINTS") or "[]")
    except ValueError:
        return []


def numbers(facts=None):
    return [f["value"] for f in (load() if facts is None else facts) if f["kind"] in ("number",)]


def addresses(facts=None):
    return [f["value"] for f in (load() if facts is None else facts) if f["kind"] == "address"]


def texts(facts=None):
    return [f["value"] for f in (load() if facts is None else facts) if f["kind"] == "text"]


if __name__ == "__main__":
    src = sys.stdin.read() if len(sys.argv) < 2 or sys.argv[1] == "-" else open(sys.argv[1], errors="replace").read()
    fs = parse(src)
    print("I read:")
    print("\n".join(describe(fs)))
    offs = offsets_from(fs)
    if offs:
        print("  offsets to try:", " ".join(map(str, offs[:10])))
