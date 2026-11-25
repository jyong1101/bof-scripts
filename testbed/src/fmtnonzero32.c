/*
 * Authorised coursework; localhost clone; dummy flag.
 * fmtnonzero64 on 32-bit, where the code is position-independent and names the global as
 * [ebx+0x..] rather than by address - the guard's test has to be found through the GOT base.
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
    if (target != 0) show("flags/fmtnonzero32.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
