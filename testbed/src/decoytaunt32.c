/*
 * Authorised coursework; localhost clone; dummy flag.
 * decoyfmt32 with a sentence instead of a format hint: "the flag is locked" matched the
 * `flag is X` pattern and `locked` was reported as the flag.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/decoytaunt32.txt", "r");
    if (!f) { puts("win, but flags/decoytaunt32.txt missing"); exit(0); }
    if (fgets(flag, sizeof flag, f)) printf("Well done: %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); puts("The flag is locked away. Overflow me."); vuln(); puts("bye"); return 0; }
