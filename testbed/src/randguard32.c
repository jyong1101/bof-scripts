/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: the guard value is RANDOM per connection and announced in the banner. It is
 * in neither the binary nor the source - the compare is against a variable - so a payload
 * prepared in advance is always wrong. The value must be read and used in one connection.
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
    want = rnd() | 0x01010101; s.code = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Session code: 0x%08x\n", want);
    printf("Name: "); gets(s.buf);              /* <-- overflow into code */
    if (s.code == want) show("flags/randguard32.txt", "Access granted.");
    else printf("Access denied. Code: 0x%08x\n", s.code);
    return 0;
}
