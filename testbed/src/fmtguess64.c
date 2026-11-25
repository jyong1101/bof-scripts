/*
 * Authorised coursework; localhost clone; dummy flag.
 * fmtguess32 on 64-bit, where a 4-byte int shares an 8-byte stack word: the secret is the
 * HIGH half of its slot, so `%d` on that slot prints the wrong number.
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
    if ((unsigned)atoi(line) == secret) show("flags/fmtguess64.txt", "Correct.");
    else puts("Nope.");
    return 0;
}
