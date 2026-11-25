/*
 * Authorised coursework; localhost clone; dummy flag.
 * ret2win WITH AN ARGUMENT, 64-bit: win(key) only prints the flag if key==0xC0DE.
 * Needs a ROP chain: pop rdi; ret -> key -> win.  A plain A*off+p64(win) cannot win.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(unsigned long key)
{
    char flag[128]; FILE *f;
    if (key != 0xC0DE) { printf("wrong key: 0x%lx\n", key); fflush(stdout); return; }
    f = fopen("flags/winarg.txt", "r");
    if (!f) { puts("win, but flags/winarg.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Correct key. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
__attribute__((used, noinline)) void rop_gadgets(void){ __asm__ volatile("pop %rdi; ret"); }

void greet(void){ char b[40]; printf("Key please: "); fflush(stdout); gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== KeyLock =="); greet(); puts("bye"); return 0; }
