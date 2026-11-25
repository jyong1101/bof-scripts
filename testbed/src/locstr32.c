/*
 * Authorised coursework; localhost clone; dummy flag.
 * A neighbouring LOCAL string compared with strcmp (role starts as "user", must be "root").
 * The literal is not what the input buffer is compared with - the neighbour is.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char role[8] = "user"; char buf[24];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Username: "); gets(buf);            /* <-- overflow into role */
    if (!strcmp(role, "root")) show("flags/locstr32.txt", "Welcome root.");
    else printf("role=%s\n", role);
    return 0;
}
