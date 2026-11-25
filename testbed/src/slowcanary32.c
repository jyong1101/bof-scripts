/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION of two features that are individually survivable and together make one
 * technique HOPELESS: a rate limit plus a canary with no leak.
 *   - canaryfork32 shows a byte-by-byte canary brute needs ~1024 connections
 *   - cyclic32 shows a 1.2s penalty per connection is survivable on its own
 * Together: 1024 x 1.2s = ~20 minutes, i.e. a fifth of a 3-hour paper spent on one
 * challenge. The right behaviour is to SAY SO, not to grind. The overflow itself is
 * ordinary, and the canary is never leaked, so there is no shortcut to find.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/slowcanary.txt", "r");
    if (!f) { puts("win, but flags/slowcanary.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Patient. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void greet(void){ char b[64]; printf("Name: "); fflush(stdout); gets(b); }
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    usleep(1200000);                  /* rate limit, as cyclic32 */
    puts("== Slow Vault ==");
    greet();                          /* canary present, never printed */
    puts("bye");
    return 0;
}
