/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: PIE behind a live gate. The code-pointer leak that makes PIE solvable is
 * printed only AFTER an arithmetic gate is answered, so anything that judges the banner
 * from the first read sees no leak and concludes PIE is hopeless. Same body as pie32,
 * which the suite already rebases; only the gate in front is new.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/gatedpie.txt", "r");
    if (!f) { puts("win, but flags/gatedpie.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Gate passed, base recovered. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void greet(void){ char b[64]; printf("Name: "); fflush(stdout); gets(b); }
int main(void)
{
    char line[128];
    int a, b;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    a = 10 + rand() % 90; b = 10 + rand() % 90;
    puts("== Gated PIE ==");
    printf("[gate 1] what is %d + %d ?\n", a, b); fflush(stdout);
    if (!fgets(line, sizeof line, stdin)) return 0;
    if (atoi(line) != a + b) { puts("wrong answer"); fflush(stdout); return 0; }
    printf("main() is at %p\n", (void *) main);     /* the leak, behind the gate */
    greet();
    puts("bye");
    return 0;
}
