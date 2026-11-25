/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: a %n write whose required value is random per connection and announced
 * ("Set target to 48213 to pass"). It is compared with a LOCAL, so the shortcut of zeroing
 * the other side of the compare is not available: the announced number must be written.
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
unsigned int target = 0;
int main(void)
{
    char buf[128]; unsigned want;
    setvbuf(stdout, NULL, _IONBF, 0);
    want = rnd() % 60000 + 1000;
    printf("Set target to %u to pass.\n", want);
    printf("Leave a message: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    printf("\n");
    if (target == want) show("flags/fmtrandlocal32.txt", "Access granted.");
    else printf("target is %u. Access denied.\n", target);
    return 0;
}
