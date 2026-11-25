/*
 * Authorised coursework; localhost clone; dummy flag.
 * The guard is TWO fields: a == 0xCAFEBABE && b == 0xDEADC0DE. Writing one constant at one
 * offset can never pass; both must be in the same payload, each at its own offset.
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
int main(void)
{
    struct { char buf[32]; unsigned a; unsigned b; } s;
    s.a = 0; s.b = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Input: "); gets(s.buf);                  /* <-- overflow into the neighbour */
    if (s.a == 0xCAFEBABE && s.b == 0xDEADC0DE) show("flags/varpair32.txt", "Both set.");
    else { printf("a=%x b=%x\n", s.a, s.b); }
    return 0;
}
