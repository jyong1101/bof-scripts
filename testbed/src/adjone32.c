/*
 * Authorised coursework; localhost clone; dummy flag.
 * `if (level == 1)`: an EXACT small value. Filler bytes make it 0x41414141, not 1, and 1 is
 * below the 0x100 floor the magic-constant scan uses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
static void show(const char *p, const char *m)
{
    char flag[128]; FILE *f = fopen(p, "r");
    if (!f) { printf("win, but %s missing\n", p); return; }
    if (fgets(flag, sizeof flag, f)) printf("%s %s\n", m, flag);
    fclose(f); fflush(stdout);
}
int main(void)
{
    struct { char buf[40]; int level; } s;
    s.level = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Input: "); gets(s.buf);                  /* <-- overflow into the neighbour */
    if (s.level == 1) show("flags/adjone32.txt", "Level one.");
    else { printf("level=%d, need 1\n", s.level); }
    return 0;
}
