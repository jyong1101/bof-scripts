/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: a LOGIN (credentials are literals in the binary) in front of a format-string
 * bug. A format probe on a bare connection lands on the username prompt and reports no bug;
 * it has to be repeated behind the login, and the engine sent down the same path.
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
unsigned int target = 0;
int main(void)
{
    char u[32], p[32], buf[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("username: "); fgets(u, sizeof u, stdin); u[strcspn(u, "\n")] = 0;
    printf("password: "); fgets(p, sizeof p, stdin); p[strcspn(p, "\n")] = 0;
    if (strcmp(u, "operator") || strcmp(p, "n1ghtsh1ft")) { puts("Login failed."); return 0; }
    printf("Welcome. Leave a note: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug, behind the login */
    printf("\n");
    if (target == 0x64) show("flags/loginfmt32.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
