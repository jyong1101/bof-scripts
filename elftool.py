#!/usr/bin/env python3
"""Stdlib-only ELF helper for the toolkit (32- and 64-bit, little-endian).

What it gives you in one shot (no pwntools, no ROPgadget):
  * protections: PIE / NX / canary / RELRO
  * PLT stub + GOT slot for every imported function (puts, printf, read, system, strdup ...)
  * gadgets by byte-scan:  jmp esp/rsp, call esp/rsp, pop ebx;ret, pop rdi;ret, ret, leave;ret
  * per-function stack-frame candidates from objdump: lea reg,[ebp-0xN] -> ret offset N+4 (N+8 on 64)
  * "win"-style symbols, and which function holds the input sink (read/gets/strcpy/fgets/scanf)

Usage:
  python3 elftool.py ./echo32                 # human report
  python3 elftool.py ./echo32 --json          # machine-readable
  python3 elftool.py ./echo32 --shift=-16     # print addresses with a uniform shift applied (note the =)

Read-only. Nothing is contacted. Authorised classroom/CTF use only.
"""
import argparse
import json
import re
import shutil
import struct
import subprocess
import sys

PT_LOAD, PT_DYNAMIC, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 0x6474E551, 0x6474E552
SHT_SYMTAB, SHT_DYNSYM, SHT_REL, SHT_RELA = 2, 11, 9, 4
SHF_EXECINSTR, SHF_WRITE = 0x4, 0x1
DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 24, 30, 0x6FFFFFFB
WIN_RE = re.compile(r"(win|flag|secret|shell|admin|success|backdoor|debug)", re.I)
SINKS = ("read", "gets", "strcpy", "fgets", "scanf", "__isoc99_scanf", "strcat", "sprintf", "memcpy", "fread")

GADGETS = {
    # name: (bytes, applies_to_bits)
    "jmp esp":            (b"\xff\xe4", 32),
    "call esp":           (b"\xff\xd4", 32),
    "jmp rsp":            (b"\xff\xe4", 64),
    "call rsp":           (b"\xff\xd4", 64),
    "pop ebx; ret":       (b"\x5b\xc3", 32),
    "pop ebp; ret":       (b"\x5d\xc3", 32),
    "pop esi; pop edi; pop ebp; ret": (b"\x5e\x5f\x5d\xc3", 32),
    "add esp,8; pop ebx; ret": (b"\x83\xc4\x08\x5b\xc3", 32),
    "pop rdi; ret":       (b"\x5f\xc3", 64),
    "pop rsi; ret":       (b"\x5e\xc3", 64),
    "pop rsi; pop r15; ret": (b"\x5e\x41\x5f\xc3", 64),
    "pop rdi; pop rsi; ret": (b"\x5f\x5e\xc3", 64),
    "pop rsi; pop rdi; ret": (b"\x5e\x5f\xc3", 64),
    "pop rdx; ret":       (b"\x5a\xc3", 64),
    "pop rbp; ret":       (b"\x5d\xc3", 64),
    "ret":                (b"\xc3", 0),
    "leave; ret":         (b"\xc9\xc3", 0),
    "int 0x80":           (b"\xcd\x80", 32),
    "syscall":            (b"\x0f\x05", 64),
}


class ELF:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        self.bits = 32 if d[4] == 1 else 64
        self.little = d[5] == 1
        if not self.little:
            raise ValueError("big-endian ELF not supported")
        if self.bits == 32:
            (self.e_type, self.e_machine, _, self.entry, self.phoff, self.shoff, _, _,
             self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = \
                struct.unpack_from("<HHIIIIIHHHHHH", d, 16)
        else:
            (self.e_type, self.e_machine, _, self.entry, self.phoff, self.shoff, _, _,
             self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx) = \
                struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
        self.pie = self.e_type == 3  # ET_DYN
        self._parse_segments()
        self._parse_sections()
        self._parse_symbols()
        self._parse_plt_got()

    # ---- parsing -------------------------------------------------------------
    def _parse_segments(self):
        self.segments = []
        for i in range(self.phnum):
            off = self.phoff + i * self.phentsize
            if self.bits == 32:
                p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = \
                    struct.unpack_from("<IIIIIIII", self.data, off)
            else:
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = \
                    struct.unpack_from("<IIQQQQQQ", self.data, off)
            self.segments.append(dict(type=p_type, offset=p_offset, vaddr=p_vaddr,
                                      filesz=p_filesz, memsz=p_memsz, flags=p_flags))
        self.nx = True
        self.relro = "none"
        for s in self.segments:
            if s["type"] == PT_GNU_STACK:
                self.nx = not (s["flags"] & 1)
            if s["type"] == PT_GNU_RELRO:
                self.relro = "partial"
        # full RELRO = RELRO segment + BIND_NOW
        for s in self.segments:
            if s["type"] == PT_DYNAMIC and self.relro == "partial":
                ent = 8 if self.bits == 32 else 16
                fmt = "<iI" if self.bits == 32 else "<qQ"
                for k in range(0, s["filesz"], ent):
                    tag, val = struct.unpack_from(fmt, self.data, s["offset"] + k)
                    if tag == 0:
                        break
                    if tag == DT_BIND_NOW or (tag == DT_FLAGS and val & 0x8) or (tag == DT_FLAGS_1 and val & 0x1):
                        self.relro = "full"

    def _parse_sections(self):
        self.sections = []
        raw = []
        for i in range(self.shnum):
            off = self.shoff + i * self.shentsize
            if self.bits == 32:
                raw.append(struct.unpack_from("<IIIIIIIIII", self.data, off))
            else:
                raw.append(struct.unpack_from("<IIQQQQIIQQ", self.data, off))
        shstr = raw[self.shstrndx] if self.shstrndx < len(raw) else None
        for r in raw:
            name_off, sh_type, flags, addr, offset, size, link, info, align, entsize = r
            name = self._cstr(shstr[4] + name_off) if shstr else ""
            self.sections.append(dict(name=name, type=sh_type, flags=flags, addr=addr,
                                      offset=offset, size=size, link=link, info=info, entsize=entsize))
        self.by_name = {s["name"]: s for s in self.sections if s["name"]}

    def _cstr(self, off):
        end = self.data.find(b"\x00", off)
        return self.data[off:end].decode("latin-1", "replace") if end >= 0 else ""

    def _read_symtab(self, sec):
        out = []
        strtab = self.sections[sec["link"]] if sec["link"] < len(self.sections) else None
        if not strtab:
            return out
        ent = 16 if self.bits == 32 else 24
        for k in range(0, sec["size"], ent):
            off = sec["offset"] + k
            if self.bits == 32:
                name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", self.data, off)
            else:
                name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, off)
            out.append(dict(name=self._cstr(strtab["offset"] + name), value=value, size=size,
                            type=info & 0xF, bind=info >> 4, shndx=shndx))
        return out

    def _parse_symbols(self):
        self.symbols = {}   # name -> addr (defined functions/objects)
        self.functions = {}  # name -> addr (STT_FUNC with value)
        self.dynsym = []
        for s in self.sections:
            if s["type"] == SHT_SYMTAB:
                for sym in self._read_symtab(s):
                    if sym["name"] and sym["value"] and sym["shndx"] != 0:
                        self.symbols[sym["name"]] = sym["value"]
                        if sym["type"] == 2:
                            self.functions[sym["name"]] = sym["value"]
            elif s["type"] == SHT_DYNSYM:
                self.dynsym = self._read_symtab(s)
        self.canary = any(n.startswith("__stack_chk_fail") for n in
                          list(self.symbols) + [d["name"] for d in self.dynsym])
        self.win_symbols = {n: a for n, a in self.functions.items() if WIN_RE.search(n)}

    def data_symbols(self):
        """Named globals that live in a WRITABLE section, e.g. `target` in .bss.

        A format-string write needs a target address. Usually it is leaked by the service,
        but on a non-PIE binary a global is simply at a fixed address in the symbol table -
        no leak required. That matters when the leak is printed somewhere the banner never
        shows, such as inside a menu option. Internal/toolchain names are dropped so the
        list stays short enough to try.
        """
        ranges = [(lo, hi) for _n, lo, hi in self.writable_slots()]
        out = {}
        for name, addr in self.symbols.items():
            if name.startswith("_") or "." in name or name in ("completed", "data_start"):
                continue
            if name in self.functions:
                continue
            if any(lo <= addr < hi for lo, hi in ranges):
                out[name] = addr
        return out

    def _parse_plt_got(self):
        """GOT slot per imported function (from .rel.plt/.rela.plt) and the PLT stub that jumps through it."""
        self.got = {}
        for s in self.sections:
            if s["type"] not in (SHT_REL, SHT_RELA) or "plt" not in s["name"]:
                continue
            if s["type"] == SHT_REL:
                ent, fmt = 8, "<II"
            else:
                ent, fmt = 24, "<QQq"
            for k in range(0, s["size"], ent):
                vals = struct.unpack_from(fmt, self.data, s["offset"] + k)
                r_offset, r_info = vals[0], vals[1]
                symidx = r_info >> (8 if self.bits == 32 else 32)
                if symidx < len(self.dynsym):
                    name = self.dynsym[symidx]["name"].split("@")[0]
                    if name:
                        self.got[name] = r_offset
        # find `jmp [got]` stubs in executable sections
        self.plt = {}
        got_to_name = {v: k for k, v in self.got.items()}
        for sec in self.sections:
            if not (sec["flags"] & SHF_EXECINSTR) or sec["size"] == 0:
                continue
            blob = self.data[sec["offset"]:sec["offset"] + sec["size"]]
            for m in re.finditer(rb"\xff\x25(....)", blob, re.S):
                disp = struct.unpack("<i" if self.bits == 64 else "<I", m.group(1))[0]
                insn_addr = sec["addr"] + m.start()
                target = (insn_addr + 6 + disp) if self.bits == 64 else disp
                name = got_to_name.get(target)
                if not name:
                    continue
                stub = insn_addr
                # include bnd prefix / endbr so we return to the stub start
                if m.start() >= 1 and blob[m.start() - 1] == 0xF2:
                    stub -= 1
                pre = blob[max(0, stub - sec["addr"] - 4):stub - sec["addr"]]
                if pre in (b"\xf3\x0f\x1e\xfb", b"\xf3\x0f\x1e\xfa"):
                    stub -= 4
                # prefer .plt.sec stubs (what `call` actually targets) over lazy .plt ones
                if name not in self.plt or sec["name"] == ".plt.sec":
                    self.plt[name] = stub

    # ---- queries -------------------------------------------------------------
    def vaddr_to_offset(self, addr):
        for s in self.segments:
            if s["type"] == PT_LOAD and s["vaddr"] <= addr < s["vaddr"] + s["filesz"]:
                return addr - s["vaddr"] + s["offset"]
        return None

    def read(self, addr, n):
        off = self.vaddr_to_offset(addr)
        return self.data[off:off + n] if off is not None else b""

    def gadgets(self):
        out = {}
        for sec in self.sections:
            if not (sec["flags"] & SHF_EXECINSTR) or sec["size"] == 0:
                continue
            blob = self.data[sec["offset"]:sec["offset"] + sec["size"]]
            for name, (pat, bits) in GADGETS.items():
                if bits and bits != self.bits:
                    continue
                for m in re.finditer(re.escape(pat), blob):
                    out.setdefault(name, []).append(sec["addr"] + m.start())
        return out

    def writable_slots(self):
        """Writable, fixed-address scratch areas (non-PIE): .bss/.data ranges."""
        out = []
        for s in self.sections:
            if s["flags"] & SHF_WRITE and s["name"] in (".bss", ".data"):
                out.append((s["name"], s["addr"], s["addr"] + s["size"]))
        return out

    def frames(self):
        """Per function: ret-offset candidates from `lea reg,[ebp-0xN]`, plus which sinks it calls."""
        if not shutil.which("objdump"):
            return {}
        try:
            txt = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", self.path],
                                 capture_output=True, text=True, timeout=20).stdout
        except Exception:
            return {}
        slot = 4 if self.bits == 32 else 8
        funcs = {}
        cur = None
        for line in txt.splitlines():
            m = re.match(r"^[0-9a-f]+ <([^>]+)>:", line)
            if m:
                cur = m.group(1)
                funcs[cur] = dict(bufs=[], sinks=[], sub=None)
                continue
            if not cur:
                continue
            m = re.search(r"lea\s+\w+,\s*\[[er]bp-0x([0-9a-f]+)\]", line)
            if m:
                n = int(m.group(1), 16)
                if n not in funcs[cur]["bufs"]:
                    funcs[cur]["bufs"].append(n)
            m = re.search(r"(?:sub\s+[er]sp,0x([0-9a-f]+)|add\s+[er]sp,0x(f[0-9a-f]{7}|f[0-9a-f]{15}))", line)
            if m and funcs[cur]["sub"] is None:
                if m.group(1):
                    funcs[cur]["sub"] = int(m.group(1), 16)
                else:
                    v = int(m.group(2), 16)
                    funcs[cur]["sub"] = (1 << (len(m.group(2)) * 4)) - v
            m = re.search(r"call\s+[0-9a-f]+ <([^>@]+)(?:@plt)?>", line)
            if m:
                callee = m.group(1)
                if callee in SINKS or re.search(r"(gets|read|strcpy|scanf|input)", callee, re.I):
                    funcs[cur]["sinks"].append(callee)
        out = {}
        for name, f in funcs.items():
            if not f["bufs"] and not f["sinks"]:
                continue
            cands = sorted({n + slot for n in f["bufs"]})
            sinks = sorted(set(f["sinks"]))
            # stdin-reaching sinks are the real overflow sources; fgets usually reads a
            # FILE (e.g. a win() flag read) so it is the weakest signal, and a win-like
            # function's buffer is almost never the overflow target.
            stdin_sinks = [s for s in sinks if re.search(r"gets|read|scanf", s, re.I) and "fgets" not in s]
            is_win = bool(WIN_RE.search(name))
            if stdin_sinks:
                prio = 0                       # definite: gets/read/scanf from stdin
            elif any("strcpy" in s or "strcat" in s or "memcpy" in s or "sprintf" in s for s in sinks):
                prio = 1                       # copy sink (argv/other buffer)
            elif sinks and not is_win:
                prio = 2                       # fgets in a non-win function (could be stdin)
            else:
                prio = 3                       # fgets inside win()/flag reader - likely a red herring
            out[name] = dict(ret_offsets=cands, sinks=sinks, frame=f["sub"],
                             priority=prio, is_win=is_win)
        return out

    def report(self):
        frames = self.frames()
        vuln = [n for n, f in frames.items() if f["sinks"]]
        rep = dict(
            file=self.path, bits=self.bits, pie=self.pie, nx=self.nx, canary=self.canary, relro=self.relro,
            entry=self.entry, plt=self.plt, got=self.got, functions=self.functions,
            win_symbols=self.win_symbols, gadgets=self.gadgets(), writable=self.writable_slots(),
            data_symbols=self.data_symbols(),
            frames=frames, vuln_functions=vuln,
        )
        # order candidate offsets by how likely the function is the real overflow:
        # stdin sinks first, win()/flag-file readers last. auto_pwn should still scan.
        vuln_sorted = sorted(vuln, key=lambda n: (frames[n]["priority"], frames[n].get("is_win", False)))
        rep["vuln_functions"] = vuln_sorted
        offs = []
        for n in vuln_sorted:
            if frames[n]["priority"] >= 3:
                continue                       # skip win()-internal flag buffers in the primary list
            for o in frames[n]["ret_offsets"]:
                if o not in offs:
                    offs.append(o)
        if not offs:                           # fall back to everything if nothing better
            for n in vuln_sorted:
                for o in frames[n]["ret_offsets"]:
                    if o not in offs:
                        offs.append(o)
        rep["ret_offset_candidates"] = offs
        return rep


def fmt_addr(a, bits):
    return f"{a:#0{10 if bits == 32 else 18}x}"


def human(rep, shift=0):
    b = rep["bits"]
    sh = f" (shift {shift:+#x} applied)" if shift else ""
    print(f"== {rep['file']} =={sh}")
    print(f"arch={b}-bit pie={rep['pie']} nx={'ON' if rep['nx'] else 'OFF (execstack)'} "
          f"canary={rep['canary']} relro={rep['relro']}")
    if rep["pie"]:
        print("note: PIE - all addresses below are offsets from the (unknown) base; a leak is needed.")
    if rep["win_symbols"]:
        print("win-like symbols: " + ", ".join(f"{n}={fmt_addr(a + shift, b)}" for n, a in rep["win_symbols"].items()))
    if rep["vuln_functions"]:
        for n in rep["vuln_functions"]:
            f = rep["frames"][n]
            print(f"sink function: {n}={fmt_addr(rep['functions'].get(n, 0) + shift, b)} calls {','.join(f['sinks'])} "
                  f"buffers at ebp-{[hex(o - (4 if b == 32 else 8)) for o in f['ret_offsets']]} "
                  f"-> RET offset candidates {f['ret_offsets']}")
    if rep["ret_offset_candidates"]:
        print("RET offset candidates (filler bytes before the saved return address):",
              ", ".join(map(str, rep["ret_offset_candidates"])))
    if rep["plt"]:
        print("imports (PLT stub / GOT slot):")
        for n in sorted(rep["plt"]):
            print(f"  {n:<16} plt={fmt_addr(rep['plt'][n] + shift, b)}  got={fmt_addr(rep['got'].get(n, 0), b)}")
    g = rep["gadgets"]
    if g:
        print("gadgets:")
        for name in ("jmp esp", "call esp", "jmp rsp", "call rsp", "pop ebx; ret", "add esp,8; pop ebx; ret",
                     "pop rdi; ret", "pop rsi; pop r15; ret", "ret", "leave; ret", "int 0x80", "syscall"):
            if name in g:
                addrs = g[name][:4]
                print(f"  {name:<26} " + " ".join(fmt_addr(a + shift, b) for a in addrs)
                      + (f" (+{len(g[name]) - 4} more)" if len(g[name]) > 4 else ""))
    if rep["writable"]:
        print("writable scratch: " + ", ".join(f"{n} {fmt_addr(lo, b)}-{fmt_addr(hi, b)}" for n, lo, hi in rep["writable"]))
    # plain-language verdict
    print("verdict:")
    if rep["win_symbols"] and not rep["pie"]:
        print("  * win-like function + fixed addresses -> ret2win:  A*offset + p(win)")
    if not rep["nx"]:
        jg = g.get("jmp esp") or g.get("jmp rsp")
        if jg:
            print(f"  * exec stack + jmp esp/rsp gadget -> ret2shellcode: A*offset + p({fmt_addr(jg[0] + shift, b)}) + NOPs + shellcode")
        else:
            print("  * exec stack, no jmp esp -> ret2shellcode needs the buffer address (printed or ASLR off)")
    if rep["nx"] and rep["plt"].get("puts") and not rep["win_symbols"]:
        print("  * NX on, no win, puts available -> ret2libc (leak puts@got, then system)")
        print("    worked example: ../exploit_echo32.py (GOT-overwrite ret2libc, no stack pivot)")
    if rep["relro"] != "full" and not rep["pie"]:
        print("  * GOT writable + fixed -> format-string %hn GOT overwrite is viable (fmt.py --write)")
    print()


def main():
    ap = argparse.ArgumentParser(description="Stdlib ELF triage: protections, PLT/GOT, gadgets, frame offsets")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--shift", default="0", help="uniform address shift to apply when printing (e.g. -16 or -0x10)")
    args = ap.parse_args()
    try:
        elf = ELF(args.binary)
    except (OSError, ValueError) as exc:
        sys.exit(f"[!] {args.binary}: {exc}")
    rep = elf.report()
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
    else:
        human(rep, int(args.shift, 0))


if __name__ == "__main__":
    main()
