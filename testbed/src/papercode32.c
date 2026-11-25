/*
 * Authorised coursework; localhost clone; dummy flag.
 * OUT OF BAND: the access code is read from a file at run time - it is not in the binary, not
 * in any source, and the service never prints it. It is "on the paper". A script with no
 * way to be TOLD a value cannot solve this, whatever it can read off the wire.
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
/* `want` is a GLOBAL on purpose. As a local it sat right after the struct, and the tools
 * solved the clone WITHOUT the paper's value by overflowing both sides of the compare to
 * the same thing - a fair exploit, but not the situation this clone is here to test. */
unsigned int want;
int main(void)
{
    struct { char name[32]; unsigned int access_code; } p;
    want = (unsigned int)secret_num("flags/papercode_secret.txt");
    p.access_code = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("=== Access Terminal ===");
    printf("Enter your name: "); gets(p.name);  /* <-- overflow into access_code */
    if (p.access_code == want) show("flags/papercode32.txt", "Access granted.");
    else puts("Access denied.");
    return 0;
}
