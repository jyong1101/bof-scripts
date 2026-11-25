/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION TEST: a live gate in front of a per-connection secret.
 *   gate 1  arithmetic on fresh numbers  - must be read and answered
 *   then    the canary is printed        - differs every connection
 *   then    the overflow                 - must put that canary back byte-for-byte
 *
 * The two mechanisms pull in opposite directions: answering the gate consumes output,
 * while the payload has to be built FROM that same connection's output. A tool that reads
 * the banner once and caches it, or that answers the gate and throws the text away, gets
 * the canary wrong and the program aborts. Same canary body as canary32, which the suite
 * already exploits.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/gatedcanary.txt", "r");
    if (!f) { puts("win, but flags/gatedcanary.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Gate passed, canary intact. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void greet(void)
{
    char b[64];
    unsigned int c;
    __asm__ volatile ("mov %%gs:0x14, %0" : "=r"(c));
    printf("canary = 0x%08x\n", c);
    printf("Name: "); fflush(stdout);
    gets(b);
    printf("hi %s\n", b); fflush(stdout);
}
int main(void)
{
    char line[128];
    int a, b;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    a = 10 + rand() % 90; b = 10 + rand() % 90;
    puts("== Gated Canary ==");
    printf("[gate 1] what is %d + %d ?\n", a, b); fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) return 0;
    if (atoi(line) != a + b) { puts("wrong answer"); fflush(stdout); return 0; }
    greet();
    puts("bye");
    return 0;
}
