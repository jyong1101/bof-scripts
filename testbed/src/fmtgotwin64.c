/*
 * Authorised coursework; localhost clone; dummy flag.
 * fmtgotwin32 on 64-bit: three %hn pieces, because an already-resolved slot holds a 6-byte
 * libc pointer whose upper bytes must be cleared too.
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
void win(void) { show("flags/fmtgotwin64.txt", "Redirected."); exit(0); }
int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Feedback: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    puts("Thanks, bye.");
    exit(0);
}
