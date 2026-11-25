/*
 * Authorised coursework; localhost clone; dummy flag.
 * BLIND: leaks nothing at all - no return address, no canary, no pointers. The only
 * signal is whether the process survives: it prints "bye" when it returns cleanly and
 * prints nothing when the saved return address is corrupted. That difference alone is
 * enough to binary-search the offset.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/blind.txt", "r");
    if (!f) { puts("win, but flags/blind.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Blind hit. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void){ char b[64]; printf("in: "); fflush(stdout); gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Blind =="); vuln(); puts("bye"); return 0; }
