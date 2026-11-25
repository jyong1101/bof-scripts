/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * UNSEEN SHAPE: deliberately combines four hostile features that no other clone mixes,
 * to test whether the toolkit COMPOSES techniques rather than pattern-matching a clone:
 *   1. 64-bit            (different packing + alignment rules)
 *   2. menu-driven       (the bug is behind option 3, not the first read)
 *   3. stack canary      (leaked in the banner, must be written back)
 *   4. win(key)          (needs a ROP chain: pop rdi -> key -> win)
 * No code was added to the toolkit for this file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"

__attribute__((used, noinline)) void rop_gadgets(void){ __asm__ volatile("pop %rdi; ret"); }

void win(unsigned long key)
{
    char flag[128]; FILE *f;
    if (key != 0xCAFE) { printf("bad key 0x%lx\n", key); fflush(stdout); return; }
    f = fopen("flags/combo.txt", "r");
    if (!f) { puts("win, but flags/combo.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Composed. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}

static void audit(void)
{
    char b[64];
    printf("Name: "); fflush(stdout);
    gets(b);
    printf("logged %s\n", b); fflush(stdout);
}

int main(void)
{
    char c[16];
    unsigned long canary;
    setvbuf(stdout, NULL, _IONBF, 0);
    __asm__ volatile ("mov %%fs:0x28, %0" : "=r"(canary));
    printf("=== Depot Mk3 ===\ncanary = 0x%016lx\n", canary);
    for (;;) {
        printf("1) Status\n2) Ping\n3) Audit\n4) Quit\nChoice: "); fflush(stdout);
        if (!fgets(c, sizeof(c), stdin)) return 0;
        if (c[0] == '3') { audit(); return 0; }
        if (c[0] == '4') return 0;
        puts("ok");
    }
}
