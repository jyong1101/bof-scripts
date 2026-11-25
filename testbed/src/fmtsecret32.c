/*
 * Authorised coursework; localhost clone; dummy flag.
 * Lab 10 Format Strings, Attack 1 exactly: `char *secret` is a local, so a POINTER to the
 * flag is on the stack and `%N$s` prints it. The flag BYTES are on the heap - a hex dump of
 * the stack never shows them. The pointer sits at slot 39, past where a slow scan gives up.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
int main(void)
{
    char buf[128]; char *secret = malloc(128);
    FILE *f = fopen("flags/fmtsecret32.txt", "r");
    if (!f) { puts("flag file missing"); return 0; }
    fgets(secret, 128, f); fclose(f);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Echo service. Say something: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    printf("\n");
    return 0;
}
