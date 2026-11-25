/* Authorised coursework; localhost clone; dummy flag.
 * strcpy sink: the copy stops at the first NUL, so no payload byte may be 0x00. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/strcpy32.txt", "r");
    if (!f) { puts("win, but flags/strcpy32.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Copied too far. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void){ char dst[64]; char src[512]; vuln_gets(src); strcpy(dst, src); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Strcpy =="); printf("say: "); fflush(stdout); vuln(); puts("bye"); return 0; }
