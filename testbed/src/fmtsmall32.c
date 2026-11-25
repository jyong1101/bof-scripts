/*
 * Authorised coursework; localhost clone; dummy flag.
 * %n write of a SMALL exact value (0x64) to a global whose address is never printed.
 * Under 0x100, so the old guard scan ignored it; and with the address at the front of the
 * string the count already exceeds small values on 64-bit. Address from the symbol table.
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
    if (target == 0x64) show("flags/fmtsmall32.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
