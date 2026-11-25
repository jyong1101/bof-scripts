#!/usr/bin/env python3
"""Will the toolkit START on the exam machine? Run this there first:  python3 compat.py

Two things localhost testing on the development box cannot show:

1. PYTHON VERSION. Python 3.12 relaxed f-strings: the same quote may be reused inside
   `{...}`, and backslashes are allowed there. Written on 3.13, such a line is a
   SyntaxError on Debian 12's Python 3.11 - the whole tool fails to import, on the day.
   A 3.12+ interpreter cannot notice by compiling, so the f-strings are checked token by
   token for exactly those constructs (and each file is compiled for real as well, which
   is the authoritative test when this runs ON the older interpreter).
2. EXTERNAL PROGRAMS. The analysis shells out to objdump / readelf / strings / nm. Without
   them it does not crash - it quietly finds nothing, which looks like "no bug here".
"""
import io, os, shutil, sys, tokenize

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = ["solve.py", "auto_pwn.py", "fmtpwn.py", "fmtwrite.py", "fmt.py", "ret2shell.py", "ret2libc.py",
         "verify.py", "elftool.py", "analyze.py", "flags.py", "bof.py", "compat.py", "notes.py", "go.py",
         os.path.join("testbed", "server.py"), os.path.join("testbed", "lagproxy.py")]
NEEDED = {"objdump": "frame offsets, guards, gadgets (binutils)",
          "readelf": "libc symbol offsets for ret2libc / GOT -> system (binutils)",
          "strings": "/bin/sh offset, flag file names (binutils)"}
OPTIONAL = {"gcc": "only to rebuild the practice clones (make -C testbed)",
            "nm": "nothing in the tools themselves; handy by hand"}


def fstring_problems(path):
    """[(line, why)] for f-string constructs that need Python 3.12+."""
    src = open(path, "rb").read()
    out = []
    if not hasattr(tokenize, "FSTRING_START"):
        return out                    # running on <= 3.11: compile() below is the real test
    stack = []                        # (quote char, start line) of enclosing f-strings
    try:
        for tok in tokenize.tokenize(io.BytesIO(src).readline):
            if tok.type == tokenize.FSTRING_START:
                q = tok.string.lstrip("rRbBfFuU")
                if stack and q[0] == stack[-1][0][0] and len(q) == len(stack[-1][0]):
                    out.append((tok.start[0], f"f-string reuses the quote {q} inside another f-string"))
                stack.append((q, tok.start[0]))
            elif tok.type == tokenize.FSTRING_END:
                if stack:
                    stack.pop()
            elif stack and tok.type == tokenize.STRING:
                q = tok.string.lstrip("rRbBfFuU")
                if q[:1] == stack[-1][0][:1] and len(stack[-1][0]) == 1 and not q.startswith(q[0] * 3):
                    out.append((tok.start[0], f"string literal {tok.string[:20]} reuses the quote of the "
                                              f"f-string it sits inside"))
                if "\\" in tok.string:
                    out.append((tok.start[0], "backslash inside an f-string expression"))
            elif stack and tok.type == tokenize.OP and tok.string == "\\":
                out.append((tok.start[0], "backslash inside an f-string expression"))
    except tokenize.TokenError as exc:
        out.append((0, f"tokenize: {exc}"))
    return out


def main():
    bad = 0
    print(f"python {sys.version.split()[0]} at {sys.executable}")
    if sys.version_info < (3, 8):
        print("  [FAIL] Python 3.8 or newer is required")
        bad += 1
    for rel in TOOLS:
        path = os.path.join(HERE, rel)
        if not os.path.exists(path):
            print(f"  [FAIL] {rel}: missing")
            bad += 1
            continue
        try:
            compile(open(path, "rb").read(), path, "exec")
        except SyntaxError as exc:
            print(f"  [FAIL] {rel}:{exc.lineno}: does not compile on THIS python: {exc.msg}")
            bad += 1
            continue
        probs = fstring_problems(path)
        for line, why in probs[:6]:
            print(f"  [FAIL] {rel}:{line}: needs Python 3.12+: {why}")
        bad += len(probs)
    if not bad:
        print(f"  [OK] {len(TOOLS)} files compile here and use no 3.12-only f-string syntax")
    for prog, why in NEEDED.items():
        if shutil.which(prog):
            print(f"  [OK] {prog}")
        else:
            print(f"  [FAIL] {prog} not found - needed for: {why}.  sudo apt install binutils")
            bad += 1
    for prog, why in OPTIONAL.items():
        if not shutil.which(prog):
            print(f"  [note] {prog} not found ({why})")
    libs = [p for p in ("/lib32/libc.so.6", "/lib/i386-linux-gnu/libc.so.6", "/usr/lib32/libc.so.6") if os.path.exists(p)]
    print("  [OK] 32-bit libc: " + libs[0] if libs else
          "  [note] no 32-bit libc here: ret2libc / GOT->system on a 32-bit target need --libc "
          "(sudo apt install libc6-i386), everything else is unaffected")
    print("COMPAT OK" if not bad else f"COMPAT FAILED ({bad} problem(s)) - fix these BEFORE the exam")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
