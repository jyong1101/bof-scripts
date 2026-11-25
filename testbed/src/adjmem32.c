/*
 * Authorised coursework; localhost clone; dummy flag.
 * Lab Q3's idea: overwrite a neighbouring STRING. role[] starts as "user" and is compared
 * with strncmp(role, "root", 4) - no NUL needed, and the literal is not the input buffer's.
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
    struct { char buf[24]; char role[8]; } s;
    memcpy(s.role, "user\0\0\0\0", 8);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Username: "); gets(s.buf);                  /* <-- overflow into the neighbour */
    if (!strncmp(s.role, "root", 4)) show("flags/adjmem32.txt", "Welcome root.");
    else { printf("role=%.8s\n", s.role); }
    return 0;
}
