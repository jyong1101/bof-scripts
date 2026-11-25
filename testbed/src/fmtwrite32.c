/*
 * Authorised coursework; localhost clone; dummy flag.
 * Format-string write of an EXACT value (bof.md section 9 step 3). `target` must become
 * precisely 0xDEADBEEF, so a single %n (which writes the running character count) is not
 * enough - it needs two 2-byte %hn writes, low half then high half.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
unsigned int target = 0;
int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("target lives at %p (currently 0x%08x)\n", (void *)&target, target);
    printf("Your input: "); fflush(stdout);
    gets(buf);
    printf(buf);                      /* <-- format-string bug */
    printf("\n");
    if (target == 0xDEADBEEF) {
        char flag[128]; FILE *f = fopen("flags/fmtwrite.txt", "r");
        if (!f) { puts("win, but flags/fmtwrite.txt missing"); return 0; }
        if (fgets(flag, sizeof(flag), f)) printf("Exact write. %s\n", flag);
        fclose(f);
    } else {
        printf("target is now 0x%08x, need 0xDEADBEEF\n", target);
    }
    fflush(stdout);
    return 0;
}
