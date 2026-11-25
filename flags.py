#!/usr/bin/env python3
"""Shared flag detection + format-string leak decoding for the toolkit.

Edge case the user flagged: the flag may or may not be wrapped in SIT{...}. So the
default matcher accepts, in priority order:
  1. SIT{...}                         (this course's format)
  2. ANYWORD{...}                     (flag{...}, CTF{...}, HTB{...}, picoCTF{...}, ...)
  3. a label like "flag is XYZ", "flag: XYZ", "the flag: XYZ"
  4. a long hex blob (>=16 hex chars), e.g. a bare md5-style token
You can always override with an explicit --flag-regex.

Also decodes format-string hex leaks (the 5004 "Echo Chamber" pattern): take the
%lx / %x words, turn each into little-endian bytes, concatenate, and pull the flag out.
"""
import re

# "Strong" = an unmistakable flag shape; "weak" = a bare token that only looks like
# one. Ordered most-specific first. The weak hex pattern is tried last and, crucially,
# a strong flag from DECODED bytes beats a weak token from the raw text (see
# decode_and_find) - that is what turns an Echo-Chamber hex dump into SIT{...}.
# The body between the braces must be PRINTABLE. `[^}]` also matched raw bytes, so stack
# words hex-decoded by a format-string leak (0x7b = '{', 0x7d = '}' turn up in addresses)
# were once reported as "FLAG: xk{\xa7`k{\xa7`r}" and the run as SOLVED. A flag is text.
STRONG_PATTERNS = [
    r"SIT\{[\x20-\x7c\x7e]{1,120}\}",
    # A short body (3-4) is believed only behind a name of 4+ characters: `ehCTF{a_b}` is a
    # flag, `U3J{hD:W}` once turned up by chance in 200 random bytes.
    r"[A-Za-z][A-Za-z0-9_]{1,15}\{[\x20-\x7c\x7e]{5,120}\}|[A-Za-z][A-Za-z0-9_]{3,15}\{[\x20-\x7c\x7e]{3,4}\}",
    r"(?:the\s+)?flag\s*(?:is|=|:)\s*([^\s,'\"]{4,})",
]
WEAK_PATTERNS = [
    r"\b[0-9a-fA-F]{16,64}\b",
]
FLAG_PATTERNS = STRONG_PATTERNS + WEAK_PATTERNS
DEFAULT_FLAG_RE = "(?i)(?:" + "|".join(f"(?:{p})" for p in FLAG_PATTERNS) + ")"


# Flag-shaped text the service prints BEFORE receiving anything: a format hint
# ("Flag format: SIT{xxxxxxxx}"), a taunt ("the flag is locked away"). It is in every
# reply, so the first payload of any kind used to be reported as having found it - a false
# SOLVED before the real exploit had run. Tools register the banner once with
# learn_ignore(); find_flag() then looks straight past those strings.
IGNORE = []
# Lengths of bare-hex tokens the service prints WITHOUT being exploited (banner, or the reply
# to a harmless input). A session id / ticket number / checksum is new on every connection,
# so the exact string cannot be learned - but its shape can. `fmtsession32` printed
# "session=<32 hex digits>" and the first overflow attempt reported it as the flag.
IGNORE_HEX_LENS = set()


def learn_ignore(banner):
    """Register every flag-shaped string in `banner` as not-a-flag. Returns the new ones."""
    text = banner.decode("latin-1", "replace") if isinstance(banner, (bytes, bytearray)) else (banner or "")
    new = []
    for pat in STRONG_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            if m.group(0) not in IGNORE:
                IGNORE.append(m.group(0))
                new.append(m.group(0))
    for pat in WEAK_PATTERNS:
        for m in re.finditer(pat, text, re.I):
            if not _repetitive(m.group(0)):
                IGNORE_HEX_LENS.add(len(m.group(0)))
    return new


def _plausible_token(tok):
    """`flag is X`: X must look like a flag, not like the next word of a sentence. "the flag
    is locked", "flag is still hidden" are English; a bare flag has a digit, an underscore
    or a brace in it, or is long (an md5-style token)."""
    return bool(re.search(r"[0-9_{}]", tok)) or len(tok) >= 16


def _repetitive(s, frac=0.6, min_distinct=5):
    """A hex token that is the attacker's own echoed payload rather than a flag.

    Two tests, because one is not enough:
      * one character dominates - 'AAAA...A', 0x41 padding echoed back, '0000...'
      * too few DISTINCT characters - 'ABABABAB...' is 50% 'A' so it passed the test
        above, yet it is just the two-byte filler echoed back. It was reported as
        "FLAG (off=20 ... filler=b'AB'): ABABABABABABABABABABABABABABABAB".
    A real bare flag (an md5-style token such as 764c6759dc7d87cf27f5cd043e167e77) uses
    most of the hex alphabet, so requiring a handful of distinct characters costs nothing.
    """
    s2 = s.lower()
    if not s2:
        return True
    if len(set(s2)) < min_distinct:
        return True
    top = max(s2.count(c) for c in set(s2))
    return top / len(s2) >= frac


def find_flag(data, regex=None, strong_only=False):
    """Return the best flag string found in bytes/str `data`, or None.

    strong_only=True ignores the bare-hex fallback, so a real SIT{...}/WORD{...} flag
    is never pre-empted by a hex blob that happens to sit earlier in the text.
    The weak bare-hex fallback additionally skips repetitive tokens (echoed padding).
    """
    text = data.decode("latin-1", "replace") if isinstance(data, (bytes, bytearray)) else data
    for known in IGNORE:
        text = text.replace(known, "")
    if regex:
        m = re.search(regex, text)
        return m.group(0) if m else None
    pats = STRONG_PATTERNS if strong_only else FLAG_PATTERNS
    for pat in pats:                          # specific -> loose, first hit wins
        if pat in WEAK_PATTERNS:              # bare hex: take the first NON-repetitive hit
            for m in re.finditer(pat, text, re.I):
                if not _repetitive(m.group(0)) and len(m.group(0)) not in IGNORE_HEX_LENS:
                    return m.group(0)
            continue
        for m in re.finditer(pat, text, re.I):
            if m.lastindex:                       # "flag is X" -> the captured token
                if _plausible_token(m.group(1)):
                    return m.group(1)
                continue
            return m.group(0)
    return None


def decode_fmt_hex(text, min_run=2):
    """Decode a format-string hex leak into ASCII (little-endian per word).

    Accepts a response like 'Hello, 6d7230667b544953 6e697274355f7440 7d7367 0 0'
    and returns the reconstructed bytes 'SIT{f0rm@t_5trings}'. Each whitespace- or
    punctuation-separated hex word is treated as one little-endian value.
    """
    # A leaked stack word is at most 16 hex digits. A LONGER unbroken run is not a list of
    # words - it is one hex-encoded string, and chopping it into 16s and reversing each
    # piece turns `SIT{...}` printed as hex into a confident, wrong `borp{TIS...}`.
    words = re.findall(r"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{%d,16})(?![0-9a-fA-F])" % min_run, text)
    out = bytearray()
    for w in words:
        if len(w) % 2:
            w = "0" + w
        try:
            out += bytes.fromhex(w)[::-1]
        except ValueError:
            pass
    return bytes(out)


LAST_HOW = "raw"          # how the most recent flag was recovered; callers may show it


def _decoded_ok(f):
    """A flag recovered by DECODING must be a convincing one: a name of 3+ characters and a
    body of 5+. Decoding manufactures text out of anything - an address dump read as base64
    gave 'mv{m1w}', 'o6{Luk}' and 'kL{{L{}' (3 in 300,000 fuzzed dumps) - so the bar is
    higher than for text the service printed in the clear."""
    if "{" not in f:
        return True                      # the "flag is X" form: judged by its own rule
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{2,15}\{[\x20-\x7c\x7e]{5,120}\}", f))


def _disguised(text):
    """A flag the service printed in another form: (flag, how) or (None, None). Only strong
    shapes count, and a decoded one must also pass _decoded_ok.

      hex       one unbroken hex run (>= 20 digits), read in order
      reversed  the text backwards
      base64    a base64 run
      rot13     letters rotated by 13
    """
    import base64, codecs
    for run in re.findall(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])", text):
        try:
            f = find_flag(bytes.fromhex(run), strong_only=True)
        except ValueError:
            f = None
        if f and _decoded_ok(f):
            return f, "hex-encoded"
    f = find_flag(text[::-1], strong_only=True)
    if f and _decoded_ok(f):
        return f, "reversed"
    for run in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        if re.fullmatch(r"[0-9a-fA-FxX]+", run):
            continue                     # an address dump, not base64: hex digits and 0x only
        try:
            f = find_flag(base64.b64decode(run + "=" * (-len(run) % 4)), strong_only=True)
        except Exception:                       # noqa: BLE001
            f = None
        if f and _decoded_ok(f):
            return f, "base64"
    f = find_flag(codecs.decode(text, "rot13"), strong_only=True)
    if f and _decoded_ok(f):
        return f, "rot13"
    return None, None


def decode_and_find(text, regex=None, strong_only=False):
    global LAST_HOW
    flag, how = _decode_and_find(text, regex, strong_only)
    if flag:
        LAST_HOW = how
    return flag, how


def _decode_and_find(text, regex=None, strong_only=False):
    """Find a flag, preferring a strong (braced/labeled) match from either the raw
    text or its little-endian-decoded hex over a weak bare-hex token.

    Order: strong-raw -> strong-decoded -> weak-raw -> weak-decoded. This is what makes
    an Echo-Chamber response ('... 6d7230667b544953 6e697274355f7440 ...') decode to
    SIT{f0rm@t_5trings} instead of stopping at the first 16-hex-char word.

    strong_only=True stops after the strong passes and never returns a weak bare-hex
    match - used for format-string leaks, where every slot is hex noise and only a
    braced/labelled flag is meaningful.
    """
    # Strip the banner's decoys BEFORE any decoding: otherwise the rot13 / reversed / base64
    # passes re-derive a "flag" from the very text the direct match was told to ignore
    # (`SIT{xxxx}` in a format hint came back as `FVG{kkkk}`).
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("latin-1", "replace")
    for known in IGNORE:
        text = text.replace(known, "")
    if regex:                                 # explicit override: honour it on raw then decoded
        f = find_flag(text, regex)
        if f:
            return f, "raw"
        f = find_flag(decode_fmt_hex(text), regex)
        return (f, "decoded-le") if f else (None, None)

    decoded = decode_fmt_hex(text)
    nul = decoded.find(b"\x00")
    clean = decoded if nul < 0 else decoded[:nul]   # drop trailing zero-words

    f = find_flag(text, strong_only=True)
    if f:
        # `FVG{...}` is a flag-shaped string too - but if rotating it gives this course's
        # own `SIT{...}`, that is what it is.
        import codecs
        r = re.search(STRONG_PATTERNS[0], codecs.decode(text, "rot13"))
        if r and not re.search(STRONG_PATTERNS[0], text):
            return r.group(0), "rot13"
        return f, "raw"
    # A wrapped flag split across little-endian stack words (the Echo Chamber shape).
    f = find_flag(clean, strong_only=True) or find_flag(decoded, strong_only=True)
    if f:
        return f, "decoded-le"
    f, how = _disguised(text)
    if f:
        return f, how
    if strong_only:
        return None, None
    f = find_flag(text)                        # weak fallbacks
    if f:
        return f, "raw"
    f = find_flag(clean) or find_flag(decoded)
    return (f, "decoded-le") if f else (None, None)


# What every tool appends to the command it types into a suspected shell, and what a real
# shell prints for it. The proof is COMPUTED: the text we send contains `$((40+2))`, never
# `42`, so nothing that merely echoes, reverses, splits or re-prints our input can show it.
PROOF_CMD = "echo SHELL$((40+2))PROOF"
PROOF_OUT = "SHELL42PROOF"


def with_proof(cmd):
    """The command to send: the caller's, followed by the proof line."""
    cmd = cmd.rstrip().rstrip(";")
    return (cmd + "; " if cmd else "") + PROOF_CMD


def shell_confirmed(text):
    """Did a shell really run our command?

    History of this check, each step a real false SOLVED on a program with no bug:
      1. `"===SHELL===" in reply` - an echo service repeats the command text.
      2. the marker on a line BY ITSELF - a service that splits its input into words and
         prints one per line (`tokecho32`) puts `===SHELL===` alone on a line.
    Evidence must be something only EXECUTION produces:
      * PROOF_OUT - the result of an arithmetic expansion we sent unevaluated, or
      * the output of `id`: `uid=<digits>(` - our command text never contains that."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("latin-1", "replace")
    return bool(PROOF_OUT in text or re.search(r"\buid=\d+\(", text))


if __name__ == "__main__":
    import sys
    data = sys.stdin.buffer.read()
    flag, how = decode_and_find(data.decode("latin-1", "replace"))
    if flag:
        print(f"{flag}   [{how}]")
    else:
        print("(no flag found; decoded bytes below)")
        print(repr(decode_fmt_hex(data.decode("latin-1", "replace"))))
