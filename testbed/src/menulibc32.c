/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION: ret2libc behind a MENU. NX on, no win(), no format bug, so the only way
 * through is leak puts@GOT -> libc base -> system("/bin/sh"). The two-stage chain has to
 * survive a menu walk: stage 1 leaks and returns into main, which prints the menu AGAIN,
 * so stage 2 must choose the option a second time. Same vuln body as ret2libc32, which
 * the suite already exploits; only the menu in front is new.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"

void vuln(void)
{
    char b[64];
    printf("say: "); fflush(stdout);
    gets(b);
}

int main(void)
{
    char c[16];
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        printf("=== Libc Depot ===\n1) Status\n2) Leave word\n3) Quit\nChoice: "); fflush(stdout);
        if (!fgets(c, sizeof(c), stdin)) return 0;
        if (c[0] == '1') { puts("All systems nominal."); fflush(stdout); }
        else if (c[0] == '2') { vuln(); return 0; }
        else return 0;
    }
}
