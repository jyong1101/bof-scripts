#!/usr/bin/env python3
"""Authorised coursework; localhost / classroom targets; dummy flags.

The front door. Nothing to remember:

    python3 go.py                                  # it asks: host, port, files, what the paper says
    python3 go.py HOST PORT                        # ...or give it what you have, in any order
    python3 go.py HOST PORT ./chall
    python3 go.py HOST PORT ./chall chall.c paper.txt

Anything that is a file is recognised by what it IS, not by where you put it: an ELF is
the binary, a .c file is the source, any other text file is the paper's notes. The notes
are read by notes.py - "buffer is 64 bytes", "win() is at 0x401186", "the code is 0x1337",
"password: hunter2", "key = 0x40 + 12" - shown back to you, and then solve.py runs with
them. If it does not solve, it asks ONCE whether the paper says anything else.

This adds nothing solve.py cannot do with --notes; it only removes the flags.
"""
import os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import notes as N           # noqa: E402


def kind_of(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    if head == b"\x7fELF":
        return "binary"
    if path.lower().endswith((".c", ".h", ".cpp")):
        return "source"
    return "notes"


def ask(prompt, default=""):
    try:
        v = input(prompt).strip()
    except EOFError:
        v = ""
    return v or default


def paste(prompt):
    """Lines until an empty one. Returns the text ('' if nothing was typed)."""
    print(prompt)
    lines = []
    while True:
        try:
            ln = input("  > ")
        except EOFError:
            break
        if not ln.strip():
            break
        lines.append(ln)
    return "\n".join(lines)


def main():
    argv = sys.argv[1:]
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    host = port = binary = source = None
    note_text, extra = "", []
    for a in argv:
        if a.startswith("--"):
            extra.append(a)
        elif os.path.isfile(a):
            k = kind_of(a)
            if k == "binary":
                binary = a
            elif k == "source":
                source = a
            elif k == "notes":
                note_text += open(a, errors="replace").read() + "\n"
        elif re.fullmatch(r"\d{1,5}", a) and port is None and host is not None:
            port = a
        elif host is None:
            host = a
        else:
            extra.append(a)
    interactive = not argv
    if host is None:
        host = ask("Host (IP or name) [127.0.0.1]: ", "127.0.0.1")
        m = re.fullmatch(r"(\S+)[\s:]+(\d{1,5})", host)         # "1.2.3.4 5001" or "1.2.3.4:5001"
        if m:
            host, port = m.group(1), m.group(2)
    if port is None:
        port = ask("Port: ")
    if not re.fullmatch(r"\d{1,5}", port or ""):
        print("[!] I need a port number (the second half of `nc HOST PORT`).")
        return 4
    if interactive:
        for label in ("A file you were given (binary or .c) - path, or Enter if none: ",
                      "Another file (Enter if none): "):
            p = ask(label)
            if not p:
                break
            p = os.path.expanduser(p.strip("'\""))
            if not os.path.isfile(p):
                print(f"   (no such file: {p} - skipped)")
                continue
            k = kind_of(p)
            if k == "binary":
                binary = p
            elif k == "source":
                source = p
            else:
                note_text += open(p, errors="replace").read() + "\n"
        if not note_text:
            note_text = paste("Does the paper tell you anything? (a size, an address, a code, a password, "
                              "a sum)\nType or paste it, then press Enter on an empty line. Enter now if nothing.")

    def run(text):
        cmd = [sys.executable, os.path.join(HERE, "solve.py"), host, port]
        if binary:
            cmd += ["--binary", binary]
        if source:
            cmd += ["--source", source]
        tmp = None
        if text.strip():
            tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
            tmp.write(text)
            tmp.close()
            cmd += ["--notes", tmp.name]
        cmd += ["--run"] + extra
        print("\n[go] " + " ".join(cmd[1:]).replace(HERE + os.sep, "") + "\n", flush=True)
        try:
            return subprocess.call(cmd)
        finally:
            if tmp:
                os.unlink(tmp.name)

    have = ", ".join(x for x in (binary and f"binary {os.path.basename(binary)}",
                                 source and f"source {os.path.basename(source)}",
                                 note_text.strip() and "notes") if x) or "nothing but the address"
    print(f"\n[go] target {host}:{port}; I have: {have}", flush=True)
    rc = run(note_text)
    if rc != 0 and sys.stdin.isatty():
        more = paste("\nNot solved yet. Is there anything ELSE on the paper - a number, an address, a size, a "
                     "password,\na sentence about what to do? Type it and press Enter twice. (Just Enter to stop.)")
        if more.strip():
            rc = run(note_text + "\n" + more)
    return rc


if __name__ == "__main__":
    sys.exit(main())
