#!/usr/bin/env python3
"""Static triage for buffer-overflow / format-string challenges.

Usage:
  python3 analyze.py buff.c form.c genie.c
  python3 analyze.py ./buff
  python3 analyze.py --json buff.c
  python3 analyze.py --quiet buff.c

Read-only. No target is contacted. Stdlib only.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

ELEM_SIZE = {"char": 1, "unsigned char": 1, "short": 2, "int": 4,
             "unsigned int": 4, "long": 4, "unsigned long": 4, "long long": 8}

ARRAY_RE = re.compile(
    r"(?P<type>(?:unsigned\s+)?(?:char|short|int|long(?:\s+long)?))\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<count>\d+)\s*\]"
)
FUNC_RE = re.compile(
    r"\b(?:void|int|char\s*\*|unsigned\s+int)\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{]*\)\s*\{"
)
FMT_VAR_RE = re.compile(r"\b(?:printf|fprintf|sprintf|vprintf)\s*\(\s*(?P<arg>[A-Za-z_]\w*)\s*(?:,|\))")
SINK_CALL_RE = re.compile(
    r"\b(?P<func>gets|strcpy|strcat|sprintf|scanf|read|memcpy|strncpy)\s*\((?P<args>[^;\n]*)\)"
)
STRCMP_RE = re.compile(
    r"strcmp\s*\(\s*(?P<buf>[A-Za-z_]\w*)\s*,\s*\"(?P<lit>[^\"]*)\"\s*\)|"
    r"strcmp\s*\(\s*\"(?P<lit2>[^\"]*)\"\s*,\s*(?P<buf2>[A-Za-z_]\w*)\s*\)"
)
FOPEN_RE = re.compile(r"fopen\s*\(\s*\"(?P<file>[^\"]+)\"")
HEX_RE = re.compile(r"0x[0-9A-Fa-f]+")


def sh(cmd, timeout=6):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except Exception as exc:
        return f"[error running {' '.join(cmd)}: {exc}]"


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def is_elf(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def parse_arrays(src):
    out = {}
    for m in ARRAY_RE.finditer(src):
        typ = " ".join(m.group("type").split())
        name = m.group("name")
        count = int(m.group("count"))
        elem = ELEM_SIZE.get(typ, 1)
        out[name] = {"type": typ, "count": count, "size": count * elem}
    return out


def first_arg(args):
    return args.split(",")[0].strip().strip("&* ")


def find_sinks(src):
    sinks = []
    for m in SINK_CALL_RE.finditer(src):
        func = m.group("func")
        args = [a.strip() for a in m.group("args").split(",")]
        buf = None
        note = ""
        if func in ("gets", "sprintf"):
            buf = first_arg(m.group("args"))
        elif func in ("strcpy", "strcat", "strncpy", "memcpy"):
            # Only count copies whose source is attacker-controlled, not a C string literal.
            if len(args) > 1 and not args[1].lstrip().startswith('"'):
                buf = first_arg(m.group("args"))
        elif func == "scanf":
            if args and '"%s"' in args[0] and len(args) > 1:
                buf = args[1].strip("&* ")
        elif func == "read":
            if len(args) >= 2:
                buf = args[1].strip("&* ")
        if buf:
            sinks.append({"func": func, "buffer": buf, "line": src[:m.start()].count("\n") + 1})
    return sinks


def find_fmt(src):
    hits = []
    for m in FMT_VAR_RE.finditer(src):
        hits.append({"func": m.group(0).split("(")[0].strip(),
                     "arg": m.group("arg"),
                     "line": src[:m.start()].count("\n") + 1})
    if "%n" in src:
        hits.append({"func": "format-string-literal", "arg": "%n", "line": None})
    return hits


def find_goals(src):
    goals = {"win_functions": [], "flag_files": [], "strcmp": [],
             "deadbeef": "0xdeadbeef" in src.lower(), "branch_checks": []}
    for m in FUNC_RE.finditer(src):
        name = m.group("name")
        if re.search(r"(win|flag|secret|shell|admin|success)", name, re.I):
            goals["win_functions"].append(name)
    goals["flag_files"] = sorted(set(FOPEN_RE.findall(src)))
    for m in STRCMP_RE.finditer(src):
        goals["strcmp"].append({"buffer": m.group("buf") or m.group("buf2"),
                                "literal": m.group("lit") or m.group("lit2")})
    for m in re.finditer(r"if\s*\([^)]*\)", src):
        text = " ".join(m.group(0).split())
        if "deadbeef" in text.lower() or "==" in text or "!=" in text:
            goals["branch_checks"].append(text)
    return goals


def find_input(src):
    out = []
    if re.search(r"\bgets\s*\(", src):
        out.append("gets() - stdin, line, unbounded")
    for m in re.finditer(r"fgets\s*\(\s*([A-Za-z_]\w*)\s*,\s*(\d+)\s*,", src):
        out.append(f"fgets({m.group(1)}, {m.group(2)}) - stdin, max {int(m.group(2)) - 1} bytes")
    for m in re.finditer(r"scanf\s*\(\s*\"([^\"]*)\"", src):
        out.append(f"scanf(%r) - stdin, whitespace-delimited" % m.group(1))
    for m in re.finditer(r"read\s*\(\s*0\s*,\s*([A-Za-z_]\w*)\s*,\s*(\d+)", src):
        out.append(f"read(0, {m.group(1)}, {m.group(2)}) - raw stdin")
    if re.search(r"argv\s*\[\s*1\s*\]", src):
        out.append("argv[1] - command-line argument")
    return out


def analyze_source(path):
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()
    src = strip_comments(raw)
    arrays = parse_arrays(src)
    sinks = find_sinks(src)
    fmt = find_fmt(src)
    goals = find_goals(src)
    inputs = find_input(src)

    classes = []
    if sinks:
        classes.append("bof")
    if fmt:
        classes.append("fmt")
    klass = "both" if len(classes) == 2 else (classes[0] if classes else "unknown")

    offsets = []
    for sink in sinks:
        buf = sink.get("buffer")
        if buf in arrays:
            size = arrays[buf]["size"]
            for delta in (0, 4, 8, 12, 16):
                cand = size + delta
                if cand not in offsets:
                    offsets.append(cand)
    offsets.sort()

    notes = []
    if fmt:
        notes.append("printf(variable) found: stack leak/write possible; try %s then %n.")
    if sinks:
        notes.append("BOF sink found: offset candidates include buffer size and frame-pointer/padding variants.")
    for s in sinks:
        if s["func"] == "strcpy":
            notes.append("strcpy stops at NUL bytes: addresses containing \\x00 will truncate.")
    if re.search(r"fgets\s*\(\s*[A-Za-z_]\w*\s*,\s*8\s*,", src):
        notes.append("fgets(...,8) only reads 7 bytes: binary may reject long payloads.")
    if "argv[1]" in src:
        notes.append("Input is argv[1], not stdin: use a local exec wrapper, not a remote socket.")
    if not re.search(r"printf\s*\(\s*\"", src) and fmt:
        notes.append("Format string used directly as printf argument.")
    if goals["deadbeef"]:
        notes.append("0xdeadbeef guard found: goal may be writing any other value (e.g. %n writes 0).")

    notes = list(dict.fromkeys(notes))

    return {
        "file": path,
        "kind": "source",
        "class": klass,
        "sinks": sinks,
        "format_strings": fmt,
        "buffers": arrays,
        "inputs": inputs,
        "goals": goals,
        "offset_candidates": offsets,
        "notes": notes,
    }


def analyze_binary(path):
    file_out = sh(["file", "-b", path])
    readelf_h = sh(["readelf", "-h", path])
    readelf_s = sh(["readelf", "-sW", path])
    readelf_l = sh(["readelf", "-lW", path])
    readelf_d = sh(["readelf", "-dW", path])
    strings = sh(["strings", "-a", path], timeout=10)

    bits = 64 if "ELF64" in readelf_h else (32 if "ELF32" in readelf_h else None)
    if "big endian" in readelf_h or "MSB" in readelf_h:
        endian = "big"
    elif "little endian" in readelf_h or "LSB" in readelf_h:
        endian = "little"
    else:
        endian = None
    is_pie = "DYN" in readelf_h and "Type:" in readelf_h and "EXEC" not in readelf_h.split("Type:")[1][:20]
    if "Type:" in readelf_h:
        type_line = [ln for ln in readelf_h.splitlines() if "Type:" in ln]
        is_pie = bool(type_line and "DYN" in type_line[0])

    funcs = []
    win_addresses = []
    for line in readelf_s.splitlines():
        if " FUNC " in line:
            parts = line.split()
            if parts:
                name = parts[-1].split("@")[0]
                funcs.append(name)
                if re.search(r"(win|flag|secret|shell|admin|success)", name, re.I) and len(parts) > 2:
                    try:
                        val = int(parts[1], 16)
                        if val:
                            win_addresses.append(val)
                    except ValueError:
                        pass
    win_syms = sorted({f for f in funcs if re.search(r"(win|flag|secret|shell|admin|success)", f, re.I)})
    has_canary = "__stack_chk_fail" in readelf_s or "__stack_chk_guard" in readelf_s
    # The name rule found nothing in the program's own code (flag function called
    # open_vault / staff_only), or the binary is statically linked and the matches are
    # libc internals: ask elftool, which also looks at what a function DOES (25 Nov).
    if not win_syms or len(funcs) > 300:
        try:
            import elftool
            _e = elftool.ELF(path)
            if _e.win_symbols or len(funcs) > 300:
                win_syms = sorted(_e.win_symbols)
                win_addresses = sorted(_e.win_symbols.values())
                if len(funcs) > 300:
                    has_canary = _e.canary
        except Exception:                           # noqa: BLE001
            pass

    nx = "unknown"
    for line in readelf_l.splitlines():
        if "GNU_STACK" in line:
            parts = line.split()
            flags = parts[-2] if len(parts) >= 2 else ""
            nx = "disabled (executable stack)" if "E" in flags else "enabled"
    relro = "none"
    if "GNU_RELRO" in readelf_l:
        relro = "full" if "BIND_NOW" in readelf_d else "partial"

    txt_files = sorted(set(re.findall(r"[\w./-]+\.txt", strings)))
    format_hits = sorted(set(re.findall(r"%[0-9$.*hlLzjt-]*[diouxXeEfFgGaAcspn%]", strings)))
    notes = []
    if is_pie:
        notes.append("PIE: runtime code address differs; a leak (or partial overwrite) is required.")
    if has_canary:
        notes.append("Stack canary: overwrite requires a leak; auto ret2win will likely fail.")
    if nx == "disabled (executable stack)":
        notes.append("NX disabled: shellcode on stack may work (lab-style).")
    elif nx == "enabled":
        notes.append("NX enabled: ret2win/ROP, not raw shellcode.")
    if win_syms:
        notes.append("Goal symbol(s): " + ", ".join(win_syms))
    if format_hits:
        notes.append("Format specifiers in binary: " + " ".join(format_hits))

    return {
        "file": path,
        "kind": "binary",
        "class": "unknown",
        "bits": bits,
        "endian": endian,
        "pie": is_pie,
        "canary": has_canary,
        "nx": nx,
        "relro": relro,
        "win_symbols": win_syms,
        "win_addresses": sorted(set(win_addresses)),
        "flag_files": txt_files,
        "format_strings": format_hits,
        "inputs": [],
        "goals": {"win_functions": win_syms, "flag_files": txt_files},
        "offset_candidates": [],
        "notes": notes,
        "file_output": file_out.strip(),
    }


def analyze(path):
    if not os.path.exists(path):
        return {"file": path, "error": "not found"}
    if is_elf(path):
        return analyze_binary(path)
    return analyze_source(path)


def suggestion(rep):
    if rep.get("kind") == "binary":
        bits = rep.get("bits") or 32
        arch = "amd64" if bits == 64 else "i386"
        return [
            f"arch={arch} endian={rep.get('endian') or 'little'} pie={rep.get('pie')} canary={rep.get('canary')} nx={rep.get('nx')}",
            "Addresses: use the program's leak; if PIE and no leak, this is not auto-solvable.",
            "Try: python3 auto_pwn.py --host H --port P --binary %s --recon" % rep["file"],
        ]
    lines = []
    if "bof" in rep["class"]:
        offs = rep["offset_candidates"][:6]
        lines.append("BOF: offset candidates " + ", ".join(map(str, offs)) + " (buffer + frame/padding).")
        lines.append("BOF: python3 auto_pwn.py --host H --port P --mode bof --source %s" % rep["file"])
    if "fmt" in rep["class"]:
        lines.append("FMT: python3 auto_pwn.py --host H --port P --mode fmt --source %s --recon" % rep["file"])
    if rep["goals"]["win_functions"]:
        lines.append("Goal function: " + ", ".join(rep["goals"]["win_functions"]))
    if rep["goals"]["strcmp"]:
        for item in rep["goals"]["strcmp"]:
            lines.append("strcmp goal: buffer %s must equal %r" % (item["buffer"], item["literal"]))
    if rep["goals"]["deadbeef"]:
        lines.append("Variable guard: 0xdeadbeef (write 0 with %n, or overwrite with any other value).")
    return lines


def human(rep):
    if "error" in rep:
        print(f"{rep['file']}: ERROR: {rep['error']}")
        return
    print(f"== {rep['file']} ==")
    print(f"kind={rep['kind']} class={rep.get('class')}")
    if rep.get("kind") == "binary":
        print(f"bits={rep.get('bits')} endian={rep.get('endian')} pie={rep.get('pie')} "
              f"canary={rep.get('canary')} nx={rep.get('nx')} relro={rep.get('relro')}")
        if rep.get("win_symbols"):
            print("win symbols:", ", ".join(rep["win_symbols"]))
        if rep.get("win_addresses"):
            print("win addresses:", ", ".join(hex(a) for a in rep["win_addresses"]))
        if rep.get("flag_files"):
            print("flag files:", ", ".join(rep["flag_files"]))
    else:
        if rep.get("buffers"):
            print("buffers:", ", ".join(f"{k}[{v['count']}]={v['size']}B" for k, v in rep["buffers"].items()))
        if rep.get("sinks"):
            print("sinks:", ", ".join(f"{s['func']}({s['buffer']})" for s in rep["sinks"]))
        if rep.get("inputs"):
            print("input:", "; ".join(rep["inputs"]))
        if rep.get("goals", {}).get("win_functions"):
            print("goal functions:", ", ".join(rep["goals"]["win_functions"]))
        if rep.get("goals", {}).get("flag_files"):
            print("flag files:", ", ".join(rep["goals"]["flag_files"]))
        if rep.get("goals", {}).get("strcmp"):
            for item in rep["goals"]["strcmp"]:
                print(f"strcmp goal: {item['buffer']} == {item['literal']!r}")
    if rep.get("offset_candidates"):
        print("offset candidates:", ", ".join(map(str, rep["offset_candidates"])))
    for note in rep.get("notes", []):
        print("note:", note)
    for line in suggestion(rep):
        print("suggest:", line)
    print()


def main():
    ap = argparse.ArgumentParser(description="Static BOF/format-string triage")
    ap.add_argument("paths", nargs="+", help="source or binary files")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--quiet", action="store_true", help="only suggestions")
    args = ap.parse_args()

    reports = [analyze(p) for p in args.paths]
    if args.json:
        print(json.dumps(reports, indent=2))
        return
    for rep in reports:
        if args.quiet and "error" not in rep:
            for line in suggestion(rep):
                print(f"{rep['file']}: {line}")
        else:
            human(rep)


if __name__ == "__main__":
    main()
