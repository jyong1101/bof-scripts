/* NOT BUILT - kept as documentation only.
 * This clone is not exploitable as written: the compiler's frame padding puts the
 * overflow somewhere harmless, so it tested nothing. `gated32` replaces it, built on
 * cyclic32's proven-exploitable body. Lesson: verify a clone can be exploited BY HAND
 * before using it to judge a tool. */
/* Authorised coursework; localhost clone; dummy flag.
 * Overflow through a hand-rolled getchar() loop: there is NO recognised sink function
 * here - no gets, no strcpy, no scanf - so a tool that finds offsets by looking up a sink
 * sees nothing and must fall back to measuring the crash empirically. That is the real
 * risk in an exam: a challenge whose read loop is written by hand.
 *
 * (A true off-by-one EBP overwrite was the original intent, but the compiler pads the
 * frame - buf lands at ebp-0x50, so buf[64] hits another local, not the saved EBP. A
 * reliable version needs hand-written asm or a packed struct; the frame-pivot technique
 * is also not implemented in this toolkit. Noted as out of scope, with the manual recipe
 * in bof.md.) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/offbyone.txt", "r");
    if (!f) { puts("win, but flags/offbyone.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Frame pivoted. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void)
{
    char buf[64];
    int i;
    printf("data: "); fflush(stdout);
    for (i = 0; i < 300; i++) {            /* no bound check at all */
        int c = getchar();
        if (c == '\n' || c == EOF) break;
        buf[i] = (char)c;
    }
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); setvbuf(stdin,NULL,_IONBF,0);
                puts("== OffByOne =="); vuln(); puts("bye"); return 0; }
