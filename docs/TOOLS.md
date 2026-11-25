# BOF Toolkit

Buffer overflow + format string. One command first; everything else is for when it refuses.
**Run from this folder's parent** (`cd the project folder`).

Proven: all four live challenges (5001–5004) solved end to end, one command each, zero
hand-typed numbers. `bash selftest.sh` gates every fix below.

---

## 0. First thing, every session

```bash
bash smoke.sh      # 30 seconds
```
Confirms gcc works, the testbed builds, and one target per technique still solves. If
this says `TOOLKIT OK` you can trust the tools; if not, run `selftest.sh` (~20 min) for
detail. Do this before you need it, not when a question is in front of you.

## 1. The one command

```bash
python3 solve.py HOST PORT --binary ./chall          # LOOK (safe, changes nothing)
python3 solve.py HOST PORT --binary ./chall --run    # SOLVE
```

Swap the file flag to match what you were given:

| You have | Use |
|---|---|
| a binary | `--binary ./chall` |
| source only | `--source ./chall.c` |
| both | both flags |
| nothing | neither flag — it still tries |

`ls` then `file *` tells you which. Real examples that worked live:

```bash
python3 solve.py HOST 5001 --source ./chall.c --run   # var/struct
python3 solve.py HOST 5002 --run                      # ret2win, no files
python3 solve.py HOST 5003 --binary ./echo32 --run    # shellcode + shift
python3 solve.py HOST 5004 --run                      # format string
```

Exit codes: **0** solved · **2** tried and failed · **3** refused · **4** bad usage (`echo $?`).

---

## 1b. Every taught shape, and what runs it

| Shape | Reached by | Proof clone |
|---|---|---|
| ret2win | `solve.py --run` | sandbox h1/h2, live 5002 |
| ret2win with an argument | automatic ROP (`pop rdi; ret`), or `--win-arg` | `testbed/winarg64` |
| 64-bit stack alignment | automatic realigning `ret` | `testbed/align64` |
| variable / struct overwrite | `--goal var`, constant from binary **or source** | `testbed/varsrc`, live 5001 |
| strcmp overwrite | `--goal strcmp` | sandbox simple_strcmp |
| format-string leak | `--mode fmt --goal fmt-leak` | live 5004 |
| format string: `%s` via a stack pointer / at a global | `fmtpwn.py` (run first by `solve.py`) | `testbed/fmtsecret32`, `fmtglobal64` |
| format string: `%hn` to a guard, any value, 32/64-bit | `fmtpwn.py` | `testbed/fmtsmall32`, `fmttarget64`, `fmtnonzero32` |
| format string: GOT -> win | `fmtpwn.py` | `testbed/fmtgotwin32/64`, `fmtgotshell32` |
| format string leak, THEN overflow (canary / PIE) | `fmtpwn.py` | `testbed/fmtcanary32/64`, `fmtpie32/64`, `fmtboth64` |
| format string leak, THEN answer a question | `fmtpwn.py` | `testbed/fmtguess32/64`, `fmtpass32` |
| small / char / boolean / two-field guard | `--goal var` (frame guards) | `testbed/adjchar32`, `adjbool32`, `adjone32`, `varpair32` |
| neighbouring string or command buffer | `--goal var` (frame guards) | `testbed/adjmem32`, `adjcmd32` |
| ret2win where win() is a shell | `solve.py --run` | `testbed/shellwin32/64` |
| ret2shellcode at a printed buffer address | `ret2shell.py` | `testbed/bufleak32/64`, `bufsmall32` |
| format-string write, any value | `--goal fmt-write` (blind probe) | sandbox genie32 |
| format-string write, EXACT value | `fmtwrite.py --addr A --value V` | `testbed/fmtwrite32` |
| **GOT overwrite -> system()** | `fmtwrite.py` + `--value-regex` + `--pre` | `testbed/got32` |
| shellcode on an exec stack | `ret2shell.py` | sandbox echo32 |
| remote build shifted | `verify.py` (confirmed by direct read) | live 5003, `testbed/chatty_echo` |
| menu / multi-step input | `--talk 'Prompt:=PAYLOAD'` | `testbed/menu32` |
| rate-limited service | `--cyclic` (one connection) | `testbed/cyclic32` |
| **PIE** | automatic rebase from a leaked code pointer | `testbed/pie32` |
| **stack canary** | automatic: leaked canary written back in place | `testbed/canary32` |
| **nothing leaked at all** | `--crash-oracle` (offset from survival) | `testbed/blind32` |
| **PIE, no leak** | `--partial` (2-byte overwrite, probabilistic) | `testbed/pieblind32` |
| **canary, no leak** | `--brute-canary` (forking services only) | `testbed/canaryfork32` |

## 2. What it does for you automatically

You should not need to type any of these. Listed so you know what to reach for if it fails.

| Handled | How |
|---|---|
| 32 vs 64-bit | from the binary, or inferred from a >32-bit leaked pointer |
| offset to the return address | read from the binary, else scanned 8→512 |
| `win()` address | ELF symbol, or scraped from the banner |
| guard constant (`== 0x1337c0de`) | `cmp` in the binary **and** `==` in the source |
| remote build shifted | `verify.py` measures it, then **confirms it by a direct read** |
| 64-bit stack alignment | retried automatically with a realigning `ret` |
| `win(key)` needing an argument | ROP chain built automatically from `cmp` constants |
| flag format | `SIT{}`, `ehCTF{}`, any `WORD{}`, `flag is X`, bare hex |
| flag not recognised | the last response is printed so you can still see it |
| flag after a shell | searched in cwd and across the filesystem |
| rate-limited service | `--cyclic` finds the offset in ONE connection |

---

## 3. The contract: it always attempts

**With `--run`, `solve.py` never declines on a reachable target.** That is the tool's
one guarantee, and it is tested: `selftest.sh` points it at full RELRO, a re-rolling
forking canary, NX-with-no-win, blind PIE, a menu service, a service that says nothing
at all, and an unknown binary protocol, and asserts none of them return exit 3.

| Exit | Means |
|---|---|
| 0 | solved |
| 2 | attempted every technique, no flag |
| 3 | **declined** - under `--run` only possible when the target is unreachable |
| 4 | bad usage |

So the question "will it try?" has a definite answer: yes, always. The question "will it
succeed?" depends on the challenge, and no tool can promise that.

With `--run`, `solve.py` never declines. If nothing is ruled *in* it tries every
technique it has, and if the service is menu-driven it walks the options itself:

```
[*] banner looks like a numbered menu (>=2 option lines)
[*] --run: walking the menu options rather than stopping.
[+] SOLVED via ret2win via menu option 2
```

When nothing was ruled in it says so first, including how long it will keep going:

```
[*] Attempting anyway: nothing was ruled IN, so every technique gets a go.
[*] Worst case this runs for 180s before giving up.
[*] Ctrl-C to stop early - on a timed paper a dead end is worth a minute, not five.
```

Exit **2** means "tried everything, no flag" - different from exit **3**, which only
happens in triage (no `--run`). **Leave `--run` off when you just want a diagnosis**:
that path still returns in under a second and tells you what it ruled out.

## 3b. What a diagnosis means

A refusal is a **correct answer**, not a failure. It prints *why each technique is ruled out*.

| It says | Meaning | Your move |
|---|---|---|
| `pie=True` **and a leaked code pointer** | base is recoverable | handled automatically |
| `pie=True`, nothing leaked | 1 unknown nibble | `--partial`, brute-forced |
| `canary=True` **and the canary is printed** | write it back in place | handled automatically |
| `canary=True`, not leaked | recoverable if the service forks | `--brute-canary` |
| `nx=ON`, no win, not a fmt bug | nothing taught applies | refuse |
| menu detected | the payload would hit the wrong read | use `--talk`, below |
| no evidence at all | no files, no leak, no fmt bug | supply a file, or refuse |

### Menus and multi-step prompts

solve.py never auto-navigates a menu — it prints a suggested chain instead. Drive it:

```bash
python3 auto_pwn.py --host H --port P --binary ./chall --goal auto \
        --talk 'Choice:=2' --talk 'Name:=PAYLOAD'
```
`EXPECT=SEND`, repeatable. `PAYLOAD` is where the exploit goes. Everything else is typed literally.

---

## 4. If it fails

| Symptom | Fix |
|---|---|
| `no flag after N attempts` | `--step 1`, `--offset-end 1200`, or pin `--offset N` |
| `max attempts (120) reached` | `--max-attempts 400` |
| flag visible in the printed tail but "no flag" | `--flag-regex 'ehCTF\{[^}]+\}'` |
| `--addr: expected a number` | you left a placeholder like `0xWIN` in |
| shell confirmed, no flag | `--interactive`, then look around by hand |
| hangs | `--noreceive` |
| every attempt slow (>1s) | rate limited — use `--cyclic` (one connection) or pin `--offset` |
| verify's shift looks wrong | it says **CONFIRMED** or it doesn't. If not, brute: `--shift=` `-0x10 0 -0x20 +0x10` |

> **The exploit is the oracle.** `verify.py` suggests a shift; `ret2shell.py` proves it.
> Six shifts take 30 seconds. Note the `=`: `--shift=-0x10` works, `--shift -0x10` does not.

### Rate-limited service

A 127-connection offset scan is hopeless if each connection costs a second. Send one
cyclic pattern instead and read the offset straight out of the leaked return address:

```bash
python3 auto_pwn.py --host H --port P --binary ./chall --goal ret2win --cyclic
```
Needs the service to print the saved return address (teaching challenges usually do).
Measured on the testbed: 12 scan attempts = 20s and no flag; `--cyclic` = 4.8s and solved.

### Writing an exact value with a format string

`--goal fmt-write` only probes blindly. For a *targeted* write (overwrite a variable or
a GOT entry with a specific value) use:

```bash
python3 fmtwrite.py H P --addr 0x804c034 --value 0xDEADBEEF
python3 fmtwrite.py H P --addr-regex 'lives at (0x[0-9a-f]+)' --value 0xDEADBEEF
```
It finds your argument slot itself, splits the value into two 2-byte halves, and works
out the cumulative `%c` padding. For GOT→`system`, get the GOT address from
`elftool.py ./chall` and pass `system`'s address as `--value`.

---

## 5. Reading the numbers

| Looks like | It is | Use |
|---|---|---|
| `0x804xxxx` / `0x40xxxx` | **code** | `--addr` target |
| `0xf7xxxxxx` | libc | not a target |
| `0xffxxxxxx` / `0x7ffxxxxxxxxx` | stack (12 hex ⇒ **64-bit**) | `%n` write target |
| `0x55xxxxxxxxxx` | PIE base | refuse |
| `40`, `76`, `216` | offset to the return address | `--offset` |
| `0x1337c0de` | guard constant | `--value` |
| `-0x10` | remote build shift | `--shift=` |

---

## 6. Which script

| Script | Use it for |
|---|---|
| **solve.py** | start here; picks the shape and runs the right tool |
| **elftool.py** | arch, protections, win symbol, offsets, gadgets |
| **auto_pwn.py** | the workhorse: ret2win / var / strcmp / fmt, `--talk`, `--win-arg` |
| **verify.py** | only: "is the server running a different build?" |
| **ret2shell.py** | only: shellcode on an executable stack |
| **fmtpwn.py** | ANY format-string challenge: read, write, GOT, leak-then-overflow, leak-then-answer; 32/64-bit, nothing typed. Also `--goal dump / read / write` by hand |
| **fmtwrite.py** | older: exact write when the service PRINTS the address/value (32-bit; GOT→system from a banner leak) |
| **fmt.py** | manual: send one exact payload, see the raw reply |
| analyze.py, flags.py, bof.py | internals; solve.py calls them |

This folder is a **BOF toolkit only** (stack overflows + format strings). Recon, web,
stego and wireless helpers are deliberately not here — different job, untested, and
keeping them would imply a coverage this does not have.

---

## 7. Testing

```bash
bash smoke.sh             # 30 s - is the toolkit working?
bash selftest.sh          # full regression suite, ~20 min
bash selftest.sh --full   # also the held-out clones in ../sandbox
```
`testbed/` holds purpose-built clones for each edge case (chatty non-echoing
service, source-only guard, `win(arg)`, stack alignment, menu). `fixtures/`
holds the real transcripts from the live 5001–5004 runs.

Deeper reading: `../bof.md` (per-challenge logic, `%n` recipe) · `RUNBOOK.md` (decision tree)
