/* Authorised coursework; localhost clone; dummy flag.
 * win() takes a POINTER to a string, not an integer: the chain must pass the address of
 * a literal that already exists in .rodata. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
const char *const PASSPHRASE = "open-sesame";
void win(const char *key)
{
    if (!key || strcmp(key, "open-sesame") != 0) {
        printf("bad key: %s\n", key ? key : "(null)"); fflush(stdout); return;
    }
    char flag[128]; FILE *f = fopen("flags/strarg.txt", "r");
    if (!f) { puts("win, but flags/strarg.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Passphrase accepted. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void gadgets(void){ __asm__ __volatile__(".byte 0x5f, 0xc3\n"); }   /* pop rdi; ret */
void vuln(void){ char b[64]; printf("key: "); fflush(stdout); vuln_gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Passphrase =="); vuln(); puts("bye"); return 0; }
