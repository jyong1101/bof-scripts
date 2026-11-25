/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: randguard32 with the value announced as a SMALL DECIMAL in a sentence
 * ("Your lucky number today is 42.") rather than as 0x-prefixed hex.
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
static unsigned rnd(void) { unsigned v; int fd = open("/dev/urandom", 0); read(fd, &v, 4); close(fd); return v; }
unsigned want;
int main(void)
{
    struct { char buf[32]; unsigned code; } s;
    want = rnd() % 90 + 10; s.code = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Your lucky number today is %u.\n", want);
    printf("Name: "); gets(s.buf);              /* <-- overflow into code */
    if (s.code == want) show("flags/smalldec32.txt", "Access granted.");
    else printf("Access denied (%u).\n", s.code);
    return 0;
}
