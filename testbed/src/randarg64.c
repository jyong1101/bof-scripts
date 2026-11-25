/*
 * Authorised coursework; localhost clone; dummy flag.
 * randarg32 on 64-bit: the announced key goes through `pop rdi; ret`, and win() loads its
 * constant-free compare from memory - the pattern that must not be confused with the
 * `mov edx, imm; cmp rax, rdx` form gcc uses for a 64-bit CONSTANT.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
static void show(const char *p, const char *m)
{
    char flag[128]; FILE *f = fopen(p, "r");
    if (!f) { printf("win, but %s missing\n", p); return; }
    if (fgets(flag, sizeof flag, f)) printf("%s %s\n", m, flag);
    fclose(f); fflush(stdout);
}
static unsigned rnd(void) { unsigned v; int fd = open("/dev/urandom", 0); read(fd, &v, 4); close(fd); return v; }
unsigned long key;
void helper(void) { __asm__("pop %rdi; ret"); }
void win(unsigned long k)
{
    if (k != key) { puts("wrong key"); exit(0); }
    show("flags/randarg64.txt", "Keyed."); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    key = rnd() | 0x01010101;
    printf("Today's key is 0x%08lx\n", key);
    vuln(); puts("bye");
    return 0;
}
