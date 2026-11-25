/*
 * Authorised coursework; localhost clone; dummy flag.
 * fmtsecret32 on 64-bit: same pointer-on-the-stack read, 8-byte slots, register args first.
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
    FILE *f = fopen("flags/fmtsecret64.txt", "r");
    if (!f) { puts("flag file missing"); return 0; }
    fgets(secret, 128, f); fclose(f);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Echo service. Say something: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    printf("\n");
    return 0;
}
