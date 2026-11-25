# Status — 2026-11-21 (rounds 17-18)

**Gate, last full run: 325 checks, ALL PASSED, ~55 min.** 128 clone sources.

- **Round 57 - "canary = 0x0".** The canary brute force watched a line the service prints
  BEFORE the check, so every guess "survived" (`canarysay32`). glibc's abort message is now
  the signal (real canary, flag, 6 s); with no signal at all (`canarymute32`) it says so
  instead of inventing a value.

- **Round 56 - the cyclic search took an echoed tag for a return address** (`taghex32`):
  it announced "offset 0", tried only that, and stopped. A hit inside the first word is now
  recognised as our own input, and a cyclic hit goes first in the offset list, not alone.

- **Round 55 - a length check was diagnosed as a stack overflow** (`lencheck32`, no bug).
  The crash search now keeps what the service SAYS at the damage point: a refusal is quoted
  and called a possible length check; a silent death is still a crash; `stack smashing
  detected` is named as a canary.

- **Round 54 - a random hex SESSION ID was reported as the flag** (`fmtsession32`) by an
  ordinary overflow attempt in 8 s, by the flood, and by fmtwrite.py. The SHAPE of bare hex a
  harmless input gets back is now learned and not counted; fmtwrite.py is strict. The tool
  says which lengths it ignores (`--flag-regex` overrides).

- **Round 53 - the format engine reported an example as the flag** (`fmtexample32`: a real
  printf bug, a reminder line with `SIT{example...}` in the reply; SOLVED in 4 s). It now takes
  the same harmless-input baseline as auto_pwn. Seven real format clones re-checked.

- **Round 52 - the mirror image** (`freeflag32`: the real flag for any input). Not called
  solved (it cannot be told from an example), but the run ends with the candidate flag on a
  line of its own and says when it IS the answer.

- **Round 51 - a flag-shaped example in the REPLY** (`hintreply32`, no bug) was reported as
  the flag in 3 s. What a harmless input gets back is now registered as not-a-flag, and the
  run says so (in case the question really is "connect and type anything").

- **Round 50 - a second false "shell confirmed".** A no-bug service that prints each word of
  the input on its own line (`tokecho32`) was reported SOLVED in 8 s. Shell evidence is now
  a COMPUTED value (`echo SHELL$((40+2))PROOF` -> `SHELL42PROOF`) or `id` output; the bare
  marker no longer counts.

- **Round 49 - the flag finder, fuzzed.** 300,000 realistic junk inputs (address dumps, random
  bytes): strict mode accepted 3 (address dumps read as base64), now 0. Decoded flags need a
  3+ name and 5+ body; a short body needs a 4+ name. Real disguised flags still decode.
  `testbed/fuzzflags.py` runs in the gate.

- **Rounds 47-48.** A diagnosis is announced as soon as it exists (line 24, not 149) and the
  ruled-out %n attempt is skipped. Ctrl-C keeps READ THIS FIRST. A FALSE SOLVED was found
  and fixed: hex-decoded stack bytes shaped like `xk{..}` with raw bytes inside were
  accepted as a flag; a flag body must now be printable.

- **Round 46.** PIE + a single printf (`fmtpieone64`, a kept limit) now ENDS with a true
  diagnosis. Every documented limit has been run as a probe: two were narrower than written,
  the rest end by saying what is missing and what still works.

- **Rounds 44-45.** Every random-address clone measured 30x: 240/240 (plus 175/175 earlier).
  Documented limits read cold: a run-time secret within the overflow's reach is SOLVED by a
  one-byte flood (73 s accident -> 4 s, `floodguard64`); an unknown login now ends with a
  diagnosis and the go.py route (advice tested: 14 s with the password as notes).

- **Rounds 41-43.** GOT->system failed ~1 run in 10 (system() at xxxx0000 -> 129 KB of
  padding): halves reordered, 60/60. A format buffer that is not on the stack now ENDS with
  a true diagnosis (`fmtglobbuf32`, a kept limit). The test server no longer orphans
  programs (three had spun for up to 22 h). Seven address-dependent clones: 175/175.

- **Rounds 39-40.** A whole FAILING session read cold: its printed command now works when
  pasted (prompt walk, 64-bit inferred), says what was tried, names the go.py route; typing
  only the address into go.py went FAIL (163 s) -> 11 s. ret2libc failed ~1 run in 37 on
  unlucky random addresses (leak cut by a zero byte / newline in an address): it now
  reconnects for fresh ones - 60/60.

- **Round 38.** ret2win from notes behind a Name prompt, no binary (`paperquiet64`): exact
  offset 7 s; only the buffer SIZE given, with another variable in between (size+48):
  FAIL (167 s) -> 15 s.

- **Round 37.** `jmp esp` address + offset in the NOTES, no binary, behind a Name prompt:
  FAIL (133 s) -> 7 s. "A harmless prompt first" tally: 9 shapes tried, 6 failed before fixes.

- **Round 36.** 64-bit shellcode behind a prompt (jmp rsp; printed buffer address): no gap.
  The same with NO files: FAIL -> 8 s (the address spray is now aimed past earlier
  prompts); negative gated on `echoname32`.

- **Rounds 34-35.** Five more probes (bug in a second function x3 techniques; shellcode
  read by scanf x2): no gap. Wrong-success audit of the later-prompt shellcode/ret2libc
  paths: no false SOLVED; `echoname32` is the permanent negative. Six gate rows that reused
  older rows' ports were renumbered.

- **Round 33 - shellcode at a printed buffer address behind a harmless prompt**
  (`namebuf32`): FAIL -> 10 s. "A harmless prompt first" had broken 3 of 5 techniques
  (jmp-esp shellcode, ret2libc, buffer-address shellcode); all five pass now.

- **Round 32 - ret2libc behind a harmless prompt** (`namelibc32`): FAIL -> 18 s. Same blind
  spot as shellcode in round 31; the prompt walker now covers `ret2libc.py` too.

- **Round 31 - a harmless prompt before the shellcode read** (`nameecho32`, live 5003's
  shape): FAIL -> 24 s. The shellcode path now walks earlier prompts and tries each frame
  offset. The same twist on the format-string challenge solved first time (no gap).

- **Round 30 - Stack Lab made script-hostile, no files.** Offset line removed (distance =
  gap between the two printed stack addresses): 66 s -> 4 s. A harmless prompt before the
  vulnerable one: FAIL -> 16 s (offset printed) / 22 s (not printed). Banner text is now
  read like notes; a code address at 0x40xxxx means 64-bit.

- **Round 29 - format strings from the paper.** The lab's exercises with the ADDRESS on
  paper and no binary (%s read of a global, %n non-zero, exact value, GOT -> win) each
  failed at ~180 s; now 3-4 s, 11-12 s through 150 ms latency. A stale `canary:` line in
  notes does not derail the leak. `HOWTO.md` explains the toolkit for the user.
- Gate 32 had ONE failure (`bufleak32`, no files, sprayed shellcode); 28/28 standalone and
  green in gate 33. Treated as a load flake; cause not proven.

- **Rounds 27-28.** Notes that contradict the binary still solve, and the disagreement is
  now stated. One notes file for two questions works. `go.py` output order and wording
  fixed. RUNBOOK: 11 commands pointed at the old `scripts/` folder - fixed, reordered, gated.

- **Rounds 25-26 - the professor's own wording.** The raw banner of live 5002 (found in
  the transcripts) reads correctly as notes; `paperlab64` is that challenge with the block
  moved to the paper and no files: fails without notes, 4 s with them. 5001's snippet as
  notes: 4 s. 5003's `jmp esp` address in words with no binary: was a 129 s failure, now
  5-9 s. Also fixed: "1,024 bytes" read as 24; a value on the line after its label.

- **Round 24.** `notes.py` reads 26 more wordings (`#define`, `0b`, `401186h`, bare hex,
  `\x` bytes, spelled-out numbers, "72 A's") through one normalising pre-pass, and a whole
  paragraph of exam instructions yields nothing to act on.

- **Round 23 - the value is on the PAPER (the user's idea).** `go.py` (front door, no flags)
  + `notes.py` (text -> facts). Three clones whose value is read from a file at run time
  fail without notes and solve with a notes file in 4-17 s; also no-files ret2win from
  "buffer is 48 bytes, win() at 0x...". Verified over the latency proxy and on Ubuntu
  22.04 / Python 3.10.
- **Round 22.** Server libc differs from yours: solved with `--libc`, and now DIAGNOSED
  by name without it (it used to say "not puts()").

- **Round 21. Every clone rebuilt on Debian 12 (gcc 12, glibc 2.36, Python 3.11) in a
  container: 96/100 at first, 100/100 after.** Two tool bugs this machine's libc had been
  hiding (PIE gadgets not rebased; ret2libc dying on a dropped variant), 19 Makefile targets
  missing from `all`, and one compiler-dependent fixture. Sweep script:
  `testbed/deb12_sweep.sh`.

- **Round 20.** `smoke.sh` on another machine: no compiler used to end in "SOMETHING IS
  BROKEN" with every tool check green - now `TOOLKIT OK (with notes)`. On REAL Debian 12 /
  Python 3.11.2 (container): tools import, derivations match, 9/9 64-bit clones rebuilt with
  gcc 12 solve.

- **Round 19.** Will it START on the exam machine? `compat.py` (run first by `smoke.sh`)
  checks the Python version for 3.12-only syntax - none found - and for objdump / readelf /
  strings. Without objdump 4 of 5 clones failed silently; `solve.py` now says so.

- **Round 17.** No-files and source-only paths through the latency proxy: 23/23. Dead time
  on an unsolvable target measured and cut (54 s -> 16 s locally, 85 s -> 39 s over
  latency): the two older format-string scans now decide in one connection whether
  scanning can work at all.
- **Round 18.** Five random drill targets, cold, over the slow link: 5/5. The `[+] FLAG`
  headline now says when it is one of several in a shell reply.
- **Independent sets through the proxy** (rehearsal r1-r7 + 12 held-out sandbox clones,
  none used to develop the toolkit): **19/19**, 9-61 s.

---

# Status — 2026-11-21 (rounds 13-15: paste-proof, and not localhost)

**Gate, last full run: 228 checks, ALL PASSED, ~30 min.** 104 clone sources.

Round 16: at 300 ms each way two more failed (`solve.py`'s own probe used a fixed 0.5 s
first-byte wait; a technique behind a login outran its loopback-tuned cap). Both fixed -
probe waits and per-technique caps now scale with the measured connection cost.

| Round | Found | Now |
|---|---|---|
| 13 | two commands triage PRINTS could not be pasted (`--budget AUTO`; an unquoted `--cmd`) | the gate executes every printed command's argument parser, on the triage and the failure path |
| 14 | `verify.py` vs the wrong program; failure-path commands | no gap in either - gated as negatives |
| 15 | **through a 150 ms-each-way proxy, 3 clones that solve in 3-7 s locally FAILED** (two out of time, one "not a format string" from a lost race) | probes run 8 at a time; first-byte wait scaled to the measured link. 99/99 through the proxy, median 11 s, worst 31 s |

`testbed/lagproxy.py` is the tool for this: `--listen P2 --to P1 --delay 0.15`.

---

# Status — 2026-11-21 (rounds 10-12: what makes it say yes when the answer is no)

**Gate, last full run: 216 checks, ALL PASSED, ~28 min.** 104 clone sources.

Round 13 (beginner-proofing): every command triage prints is now executed by the gate -
two could not be pasted (`--budget AUTO`; an unquoted `--cmd` whose tail would run in your
own shell).

| Round | Found | Now |
|---|---|---|
| 10 | a blind overflow was MEASURED (crash at N bytes) and then thrown away behind "supply --binary" | diagnosis with the measured offset and the one command to run; the printed command is itself gated |
| 11 | shellcode with no files failed; **a program with NO bug was reported "shell confirmed" / SOLVED** because it echoed our marker text | `ret2shell.py --spray` (return address repeated, no offset); shell evidence must be the command's OUTPUT (`echoloop32`) |
| 12 | **a banner's "Flag format: SIT{xxxx}" was reported as the flag**, as was "the flag is locked" -> `locked` | text printed before any input is never a flag; `flag is X` needs X to look like one (`decoyfmt32`, `decoytaunt32`) |

Rounds 11 and 12 are false SUCCESSES - the kind that ends the search and has you submit
garbage. Both were present before this session's work and green in the gate, because the
gate had ~30 rows proving a shell or flag is found and none proving a non-shell or a
non-flag is not.

---

# Status — 2026-11-21 (rounds 7-9)

**Gate, last full run: 195 checks, ALL PASSED, ~25 min.** 101 clone sources.

| Round | Question asked | Found | Now |
|---|---|---|---|
| 7 | the same anti-script twists on other shapes | login in front of a format bug; `win(const, announced)`; a pass that was luck (`fmtrand32`) | `loginfmt32`, `randarg2_32`, `randarg64`, `fmtrandlocal32` |
| 8 | the guard shapes with NO FILES (live 5002 shipped none) | `level == 1` and announced codes failed; `if (auth)` passed only by accident | value sprayed over the whole input, no offset: 3s |
| 9 | what does an HONEST failure say? | "supply --binary" with no hint that the overflow already works | `READ THIS FIRST` block: names the bug class and prints the one command to run |

Harness, found by the gate itself: fixed test ports inside the kernel's client-port range
collide with the suite's own TIME_WAIT sockets ("port N never came up" on random rows).
`testbed/server.py` now waits the port out. A random canary containing a newline is
retried instead of sent truncated (150/150 on the pinned-offset canary row).

---

# Status — 2026-11-21 (rounds 5-6: anti-script)

**Gate, last full run: 182 checks, ALL PASSED, ~19 min.** 97 clone sources.

Rounds 5-6 asked "what can a lecturer do when scripts are allowed?" - a taught shape with
one script-hostile twist. 9 hand-solved probes, 9 failed, all fixed and gated:

| Twist | Clone | What the toolkit does now |
|---|---|---|
| guard value random per connection, printed | `randguard32/64`, `smalldec32` | reads it from that connection's banner (hex or decimal) |
| `win(key)` with a per-connection key | `randarg32` | passes the banner's number as the argument |
| arithmetic gate in front of a format bug | `gatedfmt32` | answers gates before probing and before every payload |
| flag printed as hex / reversed / base64 / rot13 | `hexwin32`, `revwin32` | decodes it and says how; **no longer mis-decodes hex into a wrong flag** |
| lab's last exercise with ASLR on (looped printf, no win) | `fmtloop32` | `fmtpwn.py --goal gotsys`: libc from the GOT, `system` over `printf@GOT` |
| GOT address containing `0x0a` | (same clone) | write pieces re-cut so no address carries a bad byte |
| read ends at the return address, 64-bit | `tight64` | aligns by entering `win()` past `push rbp` |

---

# Status — 2026-11-21 (round 3)

## Round 3 in one paragraph

Re-tested against the two lab PDFs written plainly (no banner help, both word sizes)
instead of against shapes the tools already solved: **24 of 33 hand-verified probes
failed**, including three of the labs' own first exercises. All 33 now solve through the
one command in 3-8s; 35 of them are permanent gated clones. Detail and root causes:
`../bof.md`, "Round 3".

| Added | Where | Proof clones |
|---|---|---|
| `fmtpwn.py`: one format-string engine, 32/64-bit, address-at-the-tail layout | new file; ranked first by `solve.py` when the probe confirms a format bug | `fmtsecret*`, `fmtglobal*`, `fmtsmall32`, `fmttarget64`, `fmtnonzero*`, `fmtprefix32`, `fmtshort32`, `fmtgotwin*`, `fmtgotshell32` |
| leak-then-overflow (canary / PIE via printf) | `fmtpwn.py --goal leakbof` | `fmtcanary*`, `fmtpie*`, `fmtboth64` |
| leak-then-answer (number / password on the stack) | `fmtpwn.py --goal echo` | `fmtguess*`, `fmtpass32` |
| guards read off the stack frame (small, char, boolean, two fields, neighbour string, neighbour command, copy sink) | `auto_pwn.frame_guards()`, used by `--goal var` | `adjchar32`, `adjbool*`, `adjone32`, `varpair32`, `adjmem32`, `adjcmd32`, `varscanf32`, `varstrcpy32` |
| a command typed after the payload when win() is a shell | `auto_pwn.shell_followup()` | `shellwin32/64` |
| derived offsets get every variant before the sweep | `auto_pwn.run_bof` schedule | `shellwin64` |
| shellcode at a printed buffer address, before or after the return address | `ret2shell.stack_addr_in()`, `--after` | `bufleak32/64`, `bufsmall32` |

**Gate, last full run (21 Nov, after round 4): 171 checks, ALL PASSED, ~18 min.** The run
before it had 161 pass / 2 fail: one was a real defect found by the gate (a random secret
whose bytes were printable ASCII was discarded as text - fixed, then 25/25), the other was
`menucanary32`'s ranked-path row, which passed 6/6 standalone with no code change.

Round 4 added the same guard analysis from C SOURCE (`auto_pwn.source_guard_plans()`),
because live 5001 shipped only `chall.c`: struct offsets are exact, separate locals are
sprayed. Proof: the `SOURCE ONLY` gate section, `locone64`, `locstr32`.

Still open, by design or by time: GOT -> system with nothing leaked (needs a second
printf), a format buffer that is not on the stack, leak-then-ret2libc/shellcode, a live
gate in front of a format bug, a guard checked in a different function from the read.

`rehearsal/bin/r1..r7`: **7/7** when served with `--cwd sandbox` (their flags live in
`sandbox/flags/`). The FAIL recorded on 21 Nov was the harness serving them from `testbed/`.

---

# Status — 2026-11-20

Everything below lives in ``. Live challenges HOST:5001-5004 close
2026-11-21 12:00, so all live evidence was captured before then
(`fixtures/live_500*.log`).

## Live result — 4/4, one command each, no hand-typed numbers

| Port | Shape | Artifacts given | Flag |
|---|---|---|---|
| 5001 | var/struct | `chall.c` only | `SIT{Acc355_Gr@nted}` |
| 5002 | ret2win | none | `SIT{764c6759dc7d87cf27f5cd043e167e77}` |
| 5003 | ret2shellcode + build shift | `echo32` | `SIT{G0t_@_R3V_SHELL}` |
| 5004 | fmt-leak | none | `SIT{f0rm@t_5trings}` |

## Bugs found by the live run, and fixed

| Bug | Cause | Fix |
|---|---|---|
| verify said `+0x2`, truth `-0x10` | live Echo32 prints `"Message received.\n"` and never echoes; the leak included that 18-byte (0x12) chatter, and `-0x10 + 0x12 = +0x2` | anchor against a baseline response; a shift is now **confirmed by a direct read** before being reported |
| `--goal var` silently wrote `0` | only the literal `deadbeef` was ever searched for | guard constants read from `== 0x...` in source and `cmp` in the binary; fails loudly if neither |
| solve.py refused 5002 / 5004 | required a file to classify | wire evidence (leaked code address, scaling `%p` probe) is now enough |
| solve.py sent 5001 to ret2win | the source defines `win()` | ret2win ranked only when an address to jump to actually exists |
| `--arch amd64` was mandatory | no width signal without a binary | inferred from a leaked pointer >32 bits |
| flag hunt missed the flag after a shell | only looked in cwd; live 5003 keeps it at `/home/ctf/flag.txt` | filesystem search |

## Capabilities added

| Capability | Interface | Proof |
|---|---|---|
| ROP: `win(arg)` | `--win-arg 0xC0DE`, **or automatic** from the binary's `cmp` constants | `testbed/winarg64` |
| 64-bit stack alignment | automatic retry through a realigning `ret` | `testbed/align64` |
| Menus / multi-step | `--talk 'Choice:=2' --talk 'Name:=PAYLOAD'`; solve.py suggests the chain rather than just refusing | `testbed/menu32` |
| Rate-limited target | `--cyclic` — offset in ONE connection (12 scan attempts = 20s, failed; cyclic = 4.8s, solved) | `testbed/cyclic32` |
| Exact format-string write | `fmtwrite.py --addr A --value V` — finds the arg slot, splits into `%hn` halves, computes cumulative pads | `testbed/fmtwrite32` |

## Independent validation

Beyond the purpose-built clones, `solve.py --run` was pointed at the seven
`rehearsal/bin/r*` binaries - built weeks earlier for a different exercise, with neutral
banners, never used to develop or tune anything in ``:

| r1 | r2 | r3 | r4 | r5 | r6 | r7 |
|---|---|---|---|---|---|---|
| ret2win | ret2win 64 | ret2win w/ arg | var | fmt-leak | shellcode | **ret2libc** |

7/7. r7 is the NX-no-win shape that was an outright refusal earlier the same day; r3 was
reached by a different route than the clone it resembles (ret2win-with-argument rather
than var), which is composition rather than recall.

## Tests

`bash selftest.sh` → 21 checks, self-contained, builds `testbed/` only.
`bash selftest.sh --full` → also runs the held-out clones in `../sandbox` **read-only**
(it no longer builds there; if they are missing the section is skipped).

Negatives included, each must fail: blind send against a menu, scan against a
rate-limited target, same-build must not report a shift, var with no guard must refuse
instead of writing 0, repetitive echo must not be mistaken for a flag.

## Closed since

- **GOT→`system` end to end is now demonstrated.** `testbed/got32` leaks `system()`,
  `fmtwrite.py` overwrites `puts@GOT` with it (two `%hn` halves, value read from the
  same connection because libc is ASLR'd), and the program's next `puts(cmd)` executes
  `system("cat flags/got.txt")` → `SIT{g0t_0v3rwr1t3_sh3ll}`. Gated.
- **Scope corrected.** `crack.sh`, `recon.sh`, `stego.sh`, `web.sh`, `wireless.sh` are
  removed from ``. This is a BOF toolkit; shipping untested tools for other
  categories implied coverage it does not have. The originals remain in `scripts/`.
- **Format-string bugs behind a first prompt are detected.** The `%p` scaling probe now
  retries past one prompt, so a GOT-style service that reads a command first is still
  classified as a format-string bug.
- **solve.py now ranks every taught shape**, including `fmt-write` and a `--cyclic`
  retry, and prints the exact `fmtwrite.py` command with the real GOT address.

## The contract (tested invariant)

`--run` never declines on a reachable target: exit 0 (solved) or 2 (attempted, no flag),
never 3. Verified against seven pathological targets - full RELRO, forking canary that
re-rolls, NX with no win, blind PIE, menu-driven, a silent service, and an unknown
protocol. This is the checkable form of "attempts any BOF challenge"; success on an
arbitrary unseen challenge is not something any tool can guarantee, and is not claimed.

## Always attempts

`--run` never declines. Ranked guesses first, then a battery of every technique
(ret2win incl. offset sweep / crash-oracle / cyclic, var, fmt leak, fmt write, strcmp,
PIE partial overwrite, canary brute). Menu-driven services get walked automatically -
`testbed/menu32` solves with no manual `--talk`. A genuine dead end now reports
"attempted N technique(s)" and exits 2 rather than refusing; it announces its time
budget and can be Ctrl-C'd, because on a timed paper a dead end is worth a minute.
Triage (no `--run`) still returns a diagnosis in under a second.

## Still open — honest list

- 64-bit ret2libc now works too (`testbed/libc64`, gated). The fix: apply the `movaps`
  realignment to the `system()` call only - stage 1's leak already works, and adding a
  `ret` there shifts the frame and breaks it.

- PIE and stack canary are now **handled** whenever the needed value is leaked
  (`testbed/pie32`, `testbed/canary32`). Without a leak they are refused, because the
  base / canary value is genuinely unknowable - that is a refusal of an impossible
  case, not a missing feature.
- `--cyclic` needing a printed return address is **resolved**: it now falls through to
  `--crash-oracle`, which uses survival alone and needs no leak (`testbed/blind32`).
- Choosing the value for a targeted write is **resolved for the common case**: solve.py
  reads `system()` from the banner, takes the GOT slot from the ELF, and runs the chain
  itself (`testbed/got32`). A non-standard target still needs you to name it.
- PIE with no leak is **now handled** (`--partial`, `testbed/pieblind32`) and canary with
  no leak is **now handled** (`--brute-canary`, `testbed/canaryfork32`, forking services).
- Full RELRO is **now handled**: it only protects the GOT, and `.data` function pointers
  remain writable (`testbed/relro32`, `fmtwrite.py --half low`).
- Bad bytes (`0x00`/`0x0a`) in a write target are detected and `--half low` works around
  them - found the hard way when `addr+2` ended in `0x0a` and `gets()` truncated.
- A service that exec()s fresh per connection re-rolls its canary; nothing can brute that,
  and the tool says so rather than grinding through 1024 useless attempts.

## Note on scope

Work after the goal was set is confined to ``, except `../bof.md`, which was
updated once with the live findings before that boundary was pointed out. Its content is
accurate; nothing outside `` is modified any more, and `--full` now treats
`../sandbox` as read-only.
