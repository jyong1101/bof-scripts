/*
 * Authorised coursework; localhost clone; dummy flag.
 * PIE with no banner leak: printf(name) leaks a return address, its low 12 bits identify
 * which one, and that gives the load base for win().
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
void win(void) { show("flags/fmtpie32.txt", "PIE beaten."); exit(0); }
void vuln(void)
{
    char name[64]; char buf[64];
    printf("Name: "); fgets(name, sizeof name, stdin);
    printf("Hello, "); printf(name);            /* <-- format-string bug: the leak */
    printf("Message: "); gets(buf);             /* <-- overflow: the use */
    puts("Stored.");
}
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
