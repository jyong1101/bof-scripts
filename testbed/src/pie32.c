/*
 * Authorised coursework; localhost clone; dummy flag.
 * PIE: every address moves each run. The banner leaks one code pointer, which is enough
 * to recover the load base (base = leaked - that symbol's file offset) and rebase win().
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/pie.txt", "r");
    if (!f) { puts("win, but flags/pie.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Rebased. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void greet(void){ char b[64]; printf("Name: "); fflush(stdout); gets(b); }
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("main() is at %p\n", (void *) main);     /* the leak */
    greet();
    puts("bye");
    return 0;
}
