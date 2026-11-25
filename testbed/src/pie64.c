/* Authorised coursework; localhost clone; dummy flag.
 * 64-bit PIE: win() address must be rebased off a leaked pointer. */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/pie64.txt", "r");
    if (!f) { puts("win, but flags/pie64.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Rebased. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void){ char b[64]; printf("msg: "); fflush(stdout); vuln_gets(b); }
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    puts("== PIE64 ==");
    printf("main() is at %p\n", (void*)main); fflush(stdout);
    vuln(); puts("bye"); return 0;
}
