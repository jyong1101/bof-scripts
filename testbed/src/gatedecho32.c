/*
 * Authorised coursework; localhost clone; dummy flag.
 * COMPOSITION: the Echo32 BUILD SHIFT behind a live gate. Body copied verbatim from
 * sandbox/src/echo.c, which verify.py already measures (-0x20); the only change is a
 * gate in main. My first attempt used a different body and failed even UN-gated, so
 * it could not judge the gate handling at all.
 */
/*
  * Authorised coursework; localhost clone; dummy flag.
 *
 * vulnerable() read()s up to 0x200 bytes into char buf[128] -> overflow of the saved
 * return address. Executable stack + a `jmp esp` gadget in helper(), no win().
 * Solve: A*offset + p(jmp esp) + NOPs + shellcode, then `cat flags/f.txt` in the shell.
 *
 * Build variants (see Makefile):
 *   echo32      the "deployed" service build
 *   echo32-pad  same source + -DPAD: a filler function shifts every later function, i.e.
 *               "the binary you downloaded is a different build" (the Echo32 lesson).
 *               Exploiting echo32 with echo32-pad's addresses needs verify.py's shift.
 *   echo32-nx   same source without -z execstack: shellcode must NOT run (negative test).
 *
 * Authorised LOCAL/classroom practice only. Dummy flag, no real secrets.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#ifdef PAD
__attribute__((used, noinline)) void build_pad(void)
{
    __asm__ volatile(".fill 16,1,0x90");
}
#endif

__attribute__((used, noinline)) void helper(void)
{
    __asm__ volatile("jmp *%esp");
}

void vulnerable(void)
{
    char buf[128];
    puts("Echo32 clone. Say something:");
    ssize_t n = read(0, buf, 0x200);
    if (n > 0)
        write(1, buf, n);
}

int main(void)
{
    char gline[128];
    int ga, gb;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    ga = 10 + rand() % 90; gb = 10 + rand() % 90;
    printf("[gate 1] what is %d + %d ?\n", ga, gb); fflush(stdout);
    if (!fgets(gline, sizeof gline, stdin)) return 0;
    if (atoi(gline) != ga + gb) { puts("wrong answer"); fflush(stdout); return 0; }
    vulnerable();
    puts("bye");
    return 0;
}
