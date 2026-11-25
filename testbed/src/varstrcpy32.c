/*
 * Authorised coursework; localhost clone; dummy flag.
 * The read is BOUNDED (fgets into 256 bytes); the overflow is the strcpy into a 32-byte
 * struct in another function, and the guard lives in that function's frame, not the read's.
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
void check(char *in)
{
    struct { char buf[32]; int level; } s;
    s.level = 0;
    strcpy(s.buf, in);                          /* <-- the overflow is the copy */
    if (s.level == 7) show("flags/varstrcpy32.txt", "Level seven.");
    else printf("level=%d, need 7\n", s.level);
}
int main(void)
{
    char tmp[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Input: "); fgets(tmp, sizeof tmp, stdin); tmp[strcspn(tmp, "\n")] = 0;
    check(tmp);
    return 0;
}
