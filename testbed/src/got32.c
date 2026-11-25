/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * GOT overwrite -> system(), the full Lab 10 chain:
 *   1. the banner leaks system()'s runtime address (libc is ASLR'd)
 *   2. you supply the command string
 *   3. printf(buf) is a format-string bug -> overwrite puts@GOT with system
 *   4. the program then calls puts(cmd), which now runs system(cmd)
 * Built partial-RELRO so .got.plt stays writable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"

char cmd[128];

int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("system() is at %p\n", (void *) system);
    printf("command: "); fflush(stdout);
    gets(cmd);
    printf("input: "); fflush(stdout);
    gets(buf);
    printf(buf);              /* <-- format-string bug: overwrite puts@GOT here */
    printf("\n");
    puts(cmd);                /* <-- now system(cmd) if puts@GOT was overwritten */
    return 0;
}
