/* Authorised coursework; localhost clone; dummy flag.
 * 64-bit adjacent-variable overwrite with a LONG guard: compiles to mov+cmp, not cmp-imm. */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
int main(void)
{
    struct { char name[64]; unsigned long guard; } s;
    setvbuf(stdout, NULL, _IONBF, 0);
    s.guard = 0;
    puts("== Var64 ==");
    printf("name: "); fflush(stdout);
    vuln_gets(s.name);
    if (s.guard == 0xfeedfaceUL) {
        char flag[128]; FILE *f = fopen("flags/var64.txt", "r");
        if (f) { if (fgets(flag, sizeof(flag), f)) printf("Guard set. %s\n", flag); fclose(f); }
        else puts("win, but flags/var64.txt missing");
    } else printf("guard = %#lx, not the magic\n", s.guard);
    fflush(stdout); return 0;
}
