/*
 * Authorised coursework; localhost clone; dummy flag.
 * fgets(buf, 24): only 23 bytes reach printf. A two-piece %hn write does not fit; a single
 * %hn of the low half does. The tool has to MEASURE the limit and pick the layout.
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
    char buf[24];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Short note (23 chars): "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug, tiny buffer */
    printf("\n");
    if (target == 0x64) show("flags/fmtshort32.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
