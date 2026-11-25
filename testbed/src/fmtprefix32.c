/*
 * Authorised coursework; localhost clone; dummy flag.
 * The program builds "Hello, <name>" and printf()s THAT: 7 characters are printed before
 * the input, inside the same call, so %n counts them, and the buffer is 7 bytes off a word
 * boundary. An exact write (0x1337) is wrong by 7 unless both are accounted for.
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
    char name[128]; char out[200];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Your name: "); fgets(name, sizeof name, stdin);
    snprintf(out, sizeof out, "Hello, %s", name);
    printf(out);                                /* <-- format-string bug, with a prefix */
    printf("\n");
    if (target == 0x1337) show("flags/fmtprefix32.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
