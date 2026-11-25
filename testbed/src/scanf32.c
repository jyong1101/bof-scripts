/*
 * Authorised coursework; localhost clone; dummy flag.
 * scanf("%s") stops at WHITESPACE, not just newline. Any payload byte that is 0x09-0x0d
 * or 0x20 truncates the input, so an address containing one cannot be delivered this way.
 * The toolkit must know that from the sink rather than failing silently.
 */
#include <stdio.h>
#include <stdlib.h>
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/scanf.txt", "r");
    if (!f) { puts("win, but flags/scanf.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Scanned. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void){ char b[64]; printf("name: "); fflush(stdout); scanf("%s", b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Scanf =="); vuln(); puts("bye"); return 0; }
