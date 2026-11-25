/*
 * Authorised coursework; localhost clone; dummy flag.
 * `level == 1` behind scanf("%s"): the value's own bytes (01 00 00 00) must survive the
 * input function. The zeros are dropped and left to the terminator and the initial value.
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
    struct { char buf[32]; int level; } s;
    s.level = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Input: "); scanf("%s", s.buf);      /* <-- overflow into level */
    if (s.level == 1) show("flags/varscanf32.txt", "Level one.");
    else printf("level=%d, need 1\n", s.level);
    return 0;
}
