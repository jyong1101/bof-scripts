/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: ret2shellcode behind a live gate. Exec stack + a jmp esp trampoline, so
 * the payload is A*offset + p(jmp esp) + NOPs + shellcode - but the gate must be answered
 * first, and ret2shell.py reads the banner for its own purposes. Same relay body as the
 * sandbox h5_shell32 clone the suite already exploits; only the gate is new.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

__attribute__((used, noinline)) void trampoline(void)
{
    __asm__ volatile("jmp *%esp");
}

void relay(void)
{
    char buf[200];
    puts("Relay node. Transmit:");
    fflush(stdout);
    ssize_t n = read(0, buf, 0x300);
    if (n > 0)
        write(1, buf, n);
}

int main(void)
{
    char line[128];
    int a, b;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    a = 10 + rand() % 90; b = 10 + rand() % 90;
    puts("== Gated Relay ==");
    printf("[gate 1] what is %d + %d ?\n", a, b); fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) return 0;
    if (atoi(line) != a + b) { puts("wrong answer"); fflush(stdout); return 0; }
    relay();
    puts("end of transmission");
    return 0;
}
