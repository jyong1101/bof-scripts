/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: a password gate in front of a per-connection canary. The canary is only
 * printed after the credentials are accepted, so the probe has to log in before it can
 * see it - and the login walk and the canary splice are separate code paths that have
 * never run together. Credentials in .rodata (as login32), canary body as canary32.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/logincanary.txt", "r");
    if (!f) { puts("win, but flags/logincanary.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Logged in, canary intact. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
static void desk(void)
{
    char n[64];
    unsigned int c;
    __asm__ volatile ("mov %%gs:0x14, %0" : "=r"(c));
    printf("canary = 0x%08x\n", c);        /* only after a successful login */
    printf("Message: "); fflush(stdout);
    gets(n);
    printf("Noted: %s\n", n); fflush(stdout);
}
int main(void)
{
    char u[64], p[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== Front Desk ==");
    printf("username: "); fflush(stdout);
    if (!fgets(u, sizeof u, stdin)) return 0;
    u[strcspn(u, "\r\n")] = 0;
    printf("password: "); fflush(stdout);
    if (!fgets(p, sizeof p, stdin)) return 0;
    p[strcspn(p, "\r\n")] = 0;
    if (strcmp(u, "warden") != 0 || strcmp(p, "br0nz3-k3y") != 0) {
        puts("access denied"); fflush(stdout); return 0;
    }
    puts("welcome, warden");
    desk();
    puts("bye");
    return 0;
}
