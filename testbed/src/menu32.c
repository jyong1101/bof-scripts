/*
 * Authorised coursework; localhost clone; dummy flag.
 * The bug sits behind a MENU: a blind single-shot payload hits the menu read, not the
 * vulnerable one. Needs a scripted conversation (--talk).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/menu.txt", "r");
    if (!f) { puts("win, but flags/menu.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Registered. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
static void reg(void){ char n[40]; printf("Name: "); fflush(stdout); gets(n); printf("Hi %s\n", n); fflush(stdout); }
int main(void)
{
    char c[16];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        printf("=== Depot ===\n1) Status\n2) Register\n3) Quit\nChoice: "); fflush(stdout);
        if (!fgets(c, sizeof(c), stdin)) return 0;
        if (c[0] == '1') { puts("All systems nominal."); fflush(stdout); }
        else if (c[0] == '2') { reg(); return 0; }
        else return 0;
    }
}
