/*
 * Authorised coursework; localhost clone; dummy flag.
 * OUT OF BAND: a login whose credentials are read from a file (not literals in .rodata, so
 * the binary does not give them away), in front of a plain ret2win. The paper states them.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vuln_compat.h"
static void show(const char *p, const char *m)
{
    char flag[128]; FILE *f = fopen(p, "r");
    if (!f) { printf("win, but %s missing\n", p); return; }
    if (fgets(flag, sizeof flag, f)) printf("%s %s\n", m, flag);
    fclose(f); fflush(stdout);
}
static unsigned long secret_num(const char *p)
{
    char b[64]; FILE *f = fopen(p, "r");
    if (!f) { puts("secret file missing"); exit(0); }
    fgets(b, sizeof b, f); fclose(f);
    return strtoul(b, NULL, 0);
}
void win(void) { show("flags/paperlogin32.txt", "Logged in and redirected."); exit(0); }
void vuln(void) { char buf[48]; printf("note: "); gets(buf); }
int main(void)
{
    char want[96], u[40], p[40], *colon; FILE *f = fopen("flags/paperlogin_secret.txt", "r");
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!f) { puts("secret file missing"); return 0; }
    fgets(want, sizeof want, f); fclose(f); want[strcspn(want, "\n")] = 0;
    colon = strchr(want, ':'); *colon = 0;
    puts("== Staff Only ==");
    printf("username: "); fgets(u, sizeof u, stdin); u[strcspn(u, "\n")] = 0;
    printf("password: "); fgets(p, sizeof p, stdin); p[strcspn(p, "\n")] = 0;
    if (strcmp(u, want) || strcmp(p, colon + 1)) { puts("Login failed."); return 0; }
    vuln(); puts("bye");
    return 0;
}
