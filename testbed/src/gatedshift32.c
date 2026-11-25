/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: a BUILD SHIFT behind a live gate. Built twice:
 *   plain  -> the "remote" service
 *   -DPAD  -> the copy you downloaded, whose .text sits 0x10 lower
 * verify.py exists to measure that shift by reading remote memory through puts, and it
 * had no prompt handling at all - so behind a gate it reads the gate's own output and
 * concludes nothing. This is the Echo32 lesson (live 5003) with one obstacle added.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "vuln_compat.h"

#ifdef PAD
__attribute__((used, noinline)) void tiny_pad(void) { __asm__ volatile("nop"); }
#endif

void win(void)
{
    char flag[128]; FILE *f = fopen("flags/gatedshift.txt", "r");
    if (!f) { puts("win, but flags/gatedshift.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Shift measured past the gate. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void relay(void){ char b[64]; printf("say: "); fflush(stdout); gets(b); }
int main(void)
{
    char line[128];
    int a, b;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    a = 10 + rand() % 90; b = 10 + rand() % 90;
    puts("== Gated Shift ==");
#ifndef NOGATE
    printf("[gate 1] what is %d + %d ?\n", a, b); fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) return 0;
    if (atoi(line) != a + b) { puts("wrong answer"); fflush(stdout); return 0; }
#else
    (void)a; (void)b; (void)line;
#endif
    relay();
    puts("bye");
    return 0;
}
