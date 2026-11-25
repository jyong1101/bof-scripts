# How this toolkit works — read this once before the exam

Everything runs from this folder: `cd bof-scripts`

| File | What it is for |
|---|---|
| **HOWTO.md** (this) | understanding what the tools do, so their output makes sense |
| RUNBOOK.md | exam-day reference: what to type in each situation |
| README.md | every tool and every option |
| STATUS.md | what has been tested |

---

## 1. The one command

```
bash smoke.sh        # once, at the start: "TOOLKIT OK" means the tools work on this machine
python3 go.py        # once per question
```

`go.py` asks four things. Press Enter to skip any you do not have.

1. **Host** and **Port** — the two halves of `nc HOST PORT` in the question.
2. **A file you were given** — the program (`./chall`) and/or its source (`chall.c`).
3. **What the paper says** — type or paste any sentence that has a number, an address,
   a password or an instruction in it. Finish with an empty line.

Or give it everything at once, in any order:

```
python3 go.py 10.0.0.5 5002 ./chall chall.c paper.txt
```

It shows what it understood from your notes, tries the likely technique first, and stops
at the first flag. The flag line starts with `[+] FLAG`.

---

## 2. What it is doing — the three bugs in the syllabus

Every memory question in this module is one of three bugs. The tool works out which by
looking at the program (if given) and by sending harmless probes to the service.

### A. Overflow into a neighbouring variable (lab: "crash / change the variable")

```
[ buffer 32 bytes ][ access_code ]        the program reads MORE than 32 bytes into buffer
```

Bytes past the end of the buffer land in the next variable. If the program checks
`access_code == 0x1337c0de`, send 32 filler bytes and then that value.

- **What the tool needs:** how many filler bytes, and the value.
- **Where it gets them:** from the source or program; from the service's banner; from
  your notes; or, with none of those, by repeating the value across the whole input.
- **In the output:** `var/struct`, `off=32 value=0x1337c0de`.

### B. Overflow into the return address (lab: "ret2win", "shellcode")

```
[ buffer ][ saved base pointer ][ return address ]
```

Past the variables is the address the function returns to. Overwrite it and the program
jumps where you say.

- **ret2win:** jump to a function that prints the flag. Needs the *offset* (bytes of
  filler before the return address) and the *address* of that function.
- **shellcode:** jump to a `jmp esp` instruction, with your own code placed right after
  it. Needs the offset and the address of the `jmp esp`. Works only if the stack is
  executable.
- **In the output:** `ret2win`, `off=40 addr=0x401186`, or `ret2shellcode`, `jmp esp gadget=...`.

The four protections the tool reports, and what each means for you:

| It says | Meaning |
|---|---|
| canary | a secret value sits before the return address; it must be leaked first |
| PIE | the program's addresses change every run; one must be leaked first |
| NX | the stack is not executable, so no shellcode — ret2win instead |
| RELRO full | the GOT cannot be overwritten (matters for format strings) |

### C. Format string (lab: `%x`, `%s`, `%n`)

The program does `printf(your_input)`. Then `%x` / `%p` print values from its stack,
`%s` prints the string at an address, and `%n` **writes** a number to an address.

- **Read the flag off the stack:** the tool prints stack words and decodes them
  (bytes are reversed inside each word; it handles that).
- **Read at an address:** "the secret is stored at 0x0804c060" → `%s` there.
- **Write a value:** "target must equal 0xDEADBEEF" → `%n` writes to `target`.
- **Redirect a function:** overwrite a GOT entry so the next `puts()` runs `win()`.
- **In the output:** `fmt engine`, `our buffer is printf argument 7`.

---

## 3. Reading the output

```
[*]   information: what it found, what it is about to try
[!]   a warning or a decision you should read
[+]   success
=== [2/9] ret2win (25s cap) - why this was chosen      one attempt out of nine
[+] FLAG (off=40 addr=0x401186): SIT{...}              the answer, and how it was reached
[+] payload: b'AAAA...\x86\x11@\x00...'                the exact bytes sent
```

- **`READ THIS FIRST`** — printed at the very end when nothing worked. It is the tool's
  best guess at *why*, with a command to try next. Read it before anything else.
- **`answers a HARMLESS input with flag-shaped text`** — the service printed something
  that looks like a flag without being exploited. The tool will not call that solved (it
  may be an example), but it prints the candidate on its own line. If the question is just
  "connect and type something", that line is your answer.
- **`prints bare hex tokens (32 digits) without being exploited`** — the service shows
  something like a session ID every time, so the tool will not mistake hex of that length
  for a flag. If your real flag is plain hex of that length, add `--flag-regex '[0-9a-f]{32}'`.
- **`ONE OF N in this reply`** — a shell printed several flags; check which belongs to
  this question.
- **`your notes say offset 76; this binary's own layout says 60`** — your notes and your
  copy of the program disagree. Either the notes are for another question, or the server
  runs a different build from your copy (it happened in the practice round).
- Everything sent and received is saved in `solve_transcript.log`.

---

## 4. When it does not solve

Work down this list; each step takes under a minute.

1. **Read `READ THIS FIRST`** at the bottom of the output.
   For a login it cannot pass, a format string it cannot write through, or a crash with
   nowhere to return to, this block says exactly what is missing and what to type next.
2. **Give it more.** Run `go.py` again and type in anything on the paper you left out:
   a size, an address, a password, a sentence. Notes can only help.
3. **Connect by hand** — `nc HOST PORT` — and look. Is there a menu or a login before the
   input? A number printed that changes each time? Tell the tool: add the line to your
   notes, e.g. `password: hunter2`.
4. **Look at the program yourself:** `python3 elftool.py ./chall` ends with a plain
   verdict of which bug it is.
5. **Move on.** Three hours, about nine categories. A stuck question is worth five
   minutes, not twenty.

---

## 5. What it cannot do

It has been tested on 108 practice programs. These it does not solve; if a question looks
like one of them, do it by hand or skip it:

- a login whose password is nowhere in the program, the banner or your notes;
- a format string whose buffer is not on the stack;
- a secret value that changes every run, is never printed, AND sits where your input
  cannot reach it (if your overflow covers both the secret and what it is compared with,
  the tool solves it by making them equal);
- anything outside the three bugs above (heap, kernel, puzzles).

---

## 6. Practise before the exam

```
bash drill.sh 1 easy       # one random practice question, flag hidden
bash drill.sh 1 hard
```

It starts a random program and tells you the port and which files you "were given".
Solve it with `go.py` as you would in the exam. Do three or four without help: the tools
have been tested far more than you have had practice driving them.
