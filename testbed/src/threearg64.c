/* Authorised coursework; localhost clone; dummy flag.
 * win(a, b, c): needs rdi, rsi AND rdx - the third register is the one usually missing. */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(unsigned long a, unsigned long b, unsigned long c)
{
    if (a != 0x1111UL || b != 0x2222UL || c != 0x3333UL) {
        printf("no: %#lx %#lx %#lx\n", a, b, c); fflush(stdout); return;
    }
    char flag[128]; FILE *f = fopen("flags/threearg.txt", "r");
    if (!f) { puts("win, but flags/threearg.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Three accepted. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void gadgets(void){ __asm__ __volatile__(".byte 0x5f, 0xc3\n.byte 0x5e, 0xc3\n.byte 0x5a, 0xc3\n"); }
void vuln(void){ char b[64]; printf("three keys: "); fflush(stdout); vuln_gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Three =="); vuln(); puts("bye"); return 0; }
