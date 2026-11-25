/* Authorised coursework; localhost clone; dummy flag.
 * win() takes TWO arguments: needs pop rdi; pop rsi; ret, not a single pop rdi. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(unsigned long a, unsigned long b)
{
    if (a != 0xdeadbeefUL || b != 0xcafebabeUL) {
        printf("wrong keys: %#lx %#lx\n", a, b); fflush(stdout); return;
    }
    char flag[128]; FILE *f = fopen("flags/twoarg.txt", "r");
    if (!f) { puts("win, but flags/twoarg.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Both keys accepted. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
/* Challenges that need multi-argument ROP always ship the gadgets; without them the
 * shape is unsolvable from the binary alone. */
void gadgets(void)
{
    __asm__ __volatile__(".byte 0x5f, 0x5e, 0xc3\n"   /* pop rdi; pop rsi; ret */
                         ".byte 0x5f, 0xc3\n"          /* pop rdi; ret */
                         ".byte 0x5e, 0xc3\n");        /* pop rsi; ret */
}
void vuln(void){ char b[64]; printf("keys please: "); fflush(stdout); vuln_gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Two Keys =="); vuln(); puts("bye"); return 0; }
