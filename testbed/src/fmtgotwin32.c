/*
 * Authorised coursework; localhost clone; dummy flag.
 * GOT overwrite -> win(), with NOTHING leaked: win() is a symbol, the GOT slot is in the ELF.
 * Which slot matters: win() itself needs puts/fopen/printf, so those cannot be redirected.
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
void win(void) { show("flags/fmtgotwin32.txt", "Redirected."); exit(0); }
int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Feedback: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    puts("Thanks, bye.");
    exit(0);
}
