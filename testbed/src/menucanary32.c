/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: a menu in front of a per-connection secret. The canary is printed only
 * after option 2 is chosen, so the payload must be built from text that appears mid-walk.
 * The menu walker and the canary splice have never met: the walker scripts a fixed
 * conversation, while the canary has to be read live from THIS connection.
 * Menu body as menu32, canary body as canary32 - both already solved alone.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/menucanary.txt", "r");
    if (!f) { puts("win, but flags/menucanary.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Menu walked, canary intact. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
static void reg(void)
{
    char n[64];
    unsigned int c;
    __asm__ volatile ("mov %%gs:0x14, %0" : "=r"(c));
    printf("canary = 0x%08x\n", c);          /* leaked only inside option 2 */
    printf("Name: "); fflush(stdout);
    gets(n);
    printf("Hi %s\n", n); fflush(stdout);
}
int main(void)
{
    char c[16];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        printf("=== Vault Depot ===\n1) Status\n2) Register\n3) Quit\nChoice: "); fflush(stdout);
        if (!fgets(c, sizeof(c), stdin)) return 0;
        if (c[0] == '1') { puts("All systems nominal."); fflush(stdout); }
        else if (c[0] == '2') { reg(); return 0; }
        else return 0;
    }
}
