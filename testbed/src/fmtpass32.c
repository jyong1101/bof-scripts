/*
 * Authorised coursework; localhost clone; dummy flag.
 * The secret is TEXT: a password read from a file into a stack buffer, then strcmp'd with
 * the next input. It is not in the binary; it is only visible as stack words through printf.
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
    char name[64]; char guess[40]; char pw[40];
    int fd;
    memset(pw, 0, sizeof pw);
    fd = open("flags/fmtpass_pw.txt", 0);
    if (fd < 0) { puts("password file missing"); return 0; }
    read(fd, pw, 39); close(fd); pw[strcspn(pw, "\n")] = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Name: "); fgets(name, sizeof name, stdin);
    printf("Hi "); printf(name);                /* <-- format-string bug: the leak */
    printf("Password: "); fgets(guess, sizeof guess, stdin); guess[strcspn(guess, "\n")] = 0;
    if (!strcmp(guess, pw)) show("flags/fmtpass32.txt", "Welcome.");
    else puts("Wrong password.");
    return 0;
}
