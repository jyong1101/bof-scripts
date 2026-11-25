/*
 * Authorised coursework; localhost clone; dummy flag.
 * Lab 10 Buffer Overflow, Attack 2: the neighbour is a single CHAR compared with a character
 * ('7' = 0x37). A one-byte value under 0x100 at a one-byte offset - invisible to a scan for
 * 4-byte magic constants.
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
    struct { char buf[8]; char i; } s;
    s.i = '1';
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Enter text: "); gets(s.buf);                  /* <-- overflow into the neighbour */
    if (s.i == '7') show("flags/adjchar32.txt", "World!");
    else { puts("Hello"); }
    return 0;
}
