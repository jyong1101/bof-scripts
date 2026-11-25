/* Authorised coursework; localhost clone; dummy flag.
 * 32-bit cdecl multi-argument win: arguments sit on the stack, no pop gadgets needed. */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(unsigned int a, unsigned int b)
{
    if (a != 0xAABBCCDD || b != 0x11223344) {
        printf("wrong: %#x %#x\n", a, b); fflush(stdout); return;
    }
    char flag[128]; FILE *f = fopen("flags/twoarg32.txt", "r");
    if (!f) { puts("win, but flags/twoarg32.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("cdecl args accepted. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void){ char b[64]; printf("two keys: "); fflush(stdout); vuln_gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Cdecl Two =="); vuln(); puts("bye"); return 0; }
