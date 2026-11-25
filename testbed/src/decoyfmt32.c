/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT (unintended, and likely): the banner states the flag FORMAT. `SIT{xxxxxxxxxxxxxxxx}`
 * is in every reply, so a matcher that takes the first flag-shaped string reports SOLVED on the
 * first payload of any kind, before the real exploit (a plain ret2win) has run.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/decoyfmt32.txt", "r");
    if (!f) { puts("win, but flags/decoyfmt32.txt missing"); exit(0); }
    if (fgets(flag, sizeof flag, f)) printf("Well done: %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); puts("Flag format: SIT{xxxxxxxxxxxxxxxx}. Good luck."); vuln(); puts("bye"); return 0; }
