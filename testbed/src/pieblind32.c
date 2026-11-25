/*
 * Authorised coursework; localhost clone; dummy flag.
 * PIE with NO leak: nothing prints an address. The load base is unknowable, but the low
 * 12 bits of any address are the page offset and never change, so overwriting just the
 * low 2 bytes of the saved return address leaves only one unknown nibble - 16 tries.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/pieblind.txt", "r");
    if (!f) { puts("win, but flags/pieblind.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Partial overwrite. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
/* read(), not gets(): gets() NUL-terminates and would clobber a third byte,
   which is exactly what makes a 2-byte partial overwrite impossible there. */
void vuln(void){ char b[64]; printf("in: "); fflush(stdout); read(0, b, 0x200); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== PieBlind =="); vuln(); puts("bye"); return 0; }
