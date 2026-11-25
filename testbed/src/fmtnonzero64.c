/*
 * Authorised coursework; localhost clone; dummy flag.
 * `if (target)`: there is no magic constant anywhere - the guard only has to become true.
 * The value comes from the test instruction beside the global, not from a cmp immediate.
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
unsigned int target = 0;
int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Leave a message: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    printf("\n");
    if (target != 0) show("flags/fmtnonzero64.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
