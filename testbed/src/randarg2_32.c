/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: win(a, b) where a is a CONSTANT in the binary (0xC0DE) and b is random per
 * connection and printed. Neither the all-constant chain nor the single announced value
 * works; the chain needs one of each, in the right order.
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
unsigned key;
void win(unsigned a, unsigned b)
{
    if (a != 0xC0DE || b != key) { puts("wrong arguments"); exit(0); }
    show("flags/randarg2_32.txt", "Both right."); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    key = rnd() | 0x01010101;
    printf("Today's key is 0x%08x\n", key);
    vuln(); puts("bye");
    return 0;
}
