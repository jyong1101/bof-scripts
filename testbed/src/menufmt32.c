/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: a format-string bug behind a MENU. The printf(buf) and the target's
 * address are both inside option 2, so the opening banner shows neither. A tool that
 * probes for a format bug on a bare connection sees an ordinary menu and rules the whole
 * technique out. Same fmt body as fmtwrite32, same menu body as menu32 - both already
 * solved alone.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
unsigned int target = 0;
static void note(void)
{
    char buf[256];
    printf("target lives at %p (currently 0x%08x)\n", (void *)&target, target);
    printf("Your note: "); fflush(stdout);
    gets(buf);
    printf(buf);                      /* <-- format-string bug, behind the menu */
    printf("\n"); fflush(stdout);
    if (target == 0xDEADBEEF) {
        char flag[128]; FILE *f = fopen("flags/menufmt.txt", "r");
        if (!f) { puts("win, but flags/menufmt.txt missing"); return; }
        if (fgets(flag, sizeof(flag), f)) printf("Exact write behind a menu. %s\n", flag);
        fclose(f); fflush(stdout); exit(0);
    }
    printf("target is 0x%08x, not the magic\n", target); fflush(stdout);
}
int main(void)
{
    char c[16];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        printf("=== Notes Depot ===\n1) Status\n2) Leave a note\n3) Quit\nChoice: "); fflush(stdout);
        if (!fgets(c, sizeof(c), stdin)) return 0;
        if (c[0] == '1') { puts("All systems nominal."); fflush(stdout); }
        else if (c[0] == '2') { note(); return 0; }
        else return 0;
    }
}
