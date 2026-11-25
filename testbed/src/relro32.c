/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * FULL RELRO: the GOT is mapped read-only, so a GOT overwrite genuinely cannot work.
 * That does not make the binary safe - .data is still writable, and this one keeps a
 * function pointer there and calls through it. Same %n write, different target.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"

static void normal(void) { puts("nothing to see here"); }

void win(void)
{
    char flag[128]; FILE *f = fopen("flags/relro.txt", "r");
    if (!f) { puts("win, but flags/relro.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("RELRO bypassed. %s\n", flag);
    fclose(f); fflush(stdout);
}

void (*handler)(void) = normal;          /* lives in .data, stays writable */

int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("handler pointer at %p, win() at %p\n", (void *) &handler, (void *) win);
    printf("say: "); fflush(stdout);
    gets(buf);
    printf(buf);                          /* format-string bug */
    printf("\n");
    handler();                            /* call through the .data pointer */
    return 0;
}
