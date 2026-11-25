/*
 * Authorised coursework; localhost clone; dummy flag.
 * A format-string READ used as an oracle: a random number is on the stack, printf(name)
 * can show it, and the next prompt asks for it. Nothing to overwrite and no flag in memory -
 * the leak has to be answered back in the SAME connection (it changes every connect).
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
    char name[64]; char line[32]; unsigned int secret;
    int fd = open("/dev/urandom", 0); read(fd, &secret, 4); close(fd); secret %= 1000000;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Name: "); fgets(name, sizeof name, stdin);
    printf("Hi "); printf(name);                /* <-- format-string bug: the leak */
    printf("Guess my number: "); fgets(line, sizeof line, stdin);
    if ((unsigned)atoi(line) == secret) show("flags/fmtguess32.txt", "Correct.");
    else puts("Nope.");
    return 0;
}
