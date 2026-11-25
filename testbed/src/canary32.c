/*
 * Authorised coursework; localhost clone; dummy flag.
 * Stack canary: overwriting it aborts the program. The lab build prints the canary, so
 * the overflow can put it back byte-for-byte and still reach the saved return address.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/canary.txt", "r");
    if (!f) { puts("win, but flags/canary.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Canary preserved. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void greet(void)
{
    char b[64];
    unsigned int c;
    __asm__ volatile ("mov %%gs:0x14, %0" : "=r"(c));
    printf("canary = 0x%08x\n", c);
    printf("Name: "); fflush(stdout);
    gets(b);
    printf("hi %s\n", b); fflush(stdout);
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== CanaryGate =="); greet(); puts("bye"); return 0; }
