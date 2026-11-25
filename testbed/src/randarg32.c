/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: win(key) where the key is random per connection and printed. The argument
 * is not a constant in the binary; it has to come off the wire and into the chain.
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
void win(unsigned k)
{
    if (k != key) { puts("wrong key"); exit(0); }
    show("flags/randarg32.txt", "Keyed."); exit(0);
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
