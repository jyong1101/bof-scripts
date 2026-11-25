/*
 * Authorised coursework; localhost clone; dummy flag.
 * Lab 10 Format Strings, last exercise (GOT -> system), with ASLR ON and nothing printed:
 * no win(), printf(input) in a loop. libc has to be leaked out of the GOT with %s, system()
 * computed, printf@GOT overwritten, and the command sent - all in one connection.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
int main(void)
{
    char b[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Echo shell. Type something (quit to exit).");
    for (;;) {
        printf("> ");
        if (!fgets(b, sizeof b, stdin)) break;
        b[strcspn(b, "\n")] = 0;
        if (!strcmp(b, "quit")) break;
        printf(b);                              /* <-- format-string bug, in a loop */
        puts("");
    }
    return 0;
}
