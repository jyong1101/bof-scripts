/*
 * Authorised coursework; localhost clone; dummy flag.
 * TWO bugs in one connection: printf(name) leaks, gets(buf) overflows. The canary is never
 * printed - the format string is the only way to read it. Nothing says which slot it is.
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
void win(void) { show("flags/fmtcanary32.txt", "Canary beaten."); exit(0); }
void vuln(void)
{
    char name[64]; char buf[64];
    printf("Name: "); fgets(name, sizeof name, stdin);
    printf("Hello, "); printf(name);            /* <-- format-string bug: the leak */
    printf("Message: "); gets(buf);             /* <-- overflow: the use */
    puts("Stored.");
}
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
