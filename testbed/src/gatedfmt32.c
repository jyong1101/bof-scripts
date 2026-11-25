/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: an arithmetic gate with fresh numbers in FRONT of a format-string bug. A
 * probe that does not answer it lands on the gate's read and concludes there is no bug.
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
static unsigned rnd(void) { unsigned v; int fd = open("/dev/urandom", 0); read(fd, &v, 4); close(fd); return v; }
unsigned int target = 0;
int main(void)
{
    char buf[128]; char line[32]; int a, b;
    setvbuf(stdout, NULL, _IONBF, 0);
    a = rnd() % 90 + 10; b = rnd() % 90 + 10;
    printf("Prove you are human: what is %d + %d ?\n", a, b);
    fgets(line, sizeof line, stdin);
    if (atoi(line) != a + b) { puts("Wrong."); return 0; }
    printf("Leave a message: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug, behind the gate */
    printf("\n");
    if (target == 0x64) show("flags/gatedfmt32.txt", "Access granted.");
    else printf("target is 0x%x. Access denied.\n", target);
    return 0;
}
