/*
 * Authorised coursework; localhost clone; dummy flag.
 * adjbool32 on 64-bit.
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
    struct { char buf[32]; int authenticated; } s;
    s.authenticated = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Password: "); gets(s.buf);                  /* <-- overflow into the neighbour */
    if (s.authenticated) show("flags/adjbool64.txt", "Welcome.");
    else { puts("Wrong password."); }
    return 0;
}
