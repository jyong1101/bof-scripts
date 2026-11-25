/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * NX on, no win(), no format-string bug: the only way through is ret2libc.
 * Leak puts@GOT by calling puts(puts@got), return into main for a second shot, work
 * out the libc base from the leak, then call system("/bin/sh").
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"

void vuln(void)
{
    char b[64];
    printf("say: "); fflush(stdout);
    gets(b);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== Libcland ==");
    vuln();
    return 0;
}
