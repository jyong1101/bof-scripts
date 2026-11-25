/*
 * Authorised coursework; localhost clone; dummy flag.
 * 64-bit ret2libc: NX on, no win(), no format bug. Needs a `pop rdi; ret` to pass the
 * argument, which 32-bit cdecl does not - the two architectures need different chains.
 */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
__attribute__((used, noinline)) void rop(void){ __asm__ volatile("pop %rdi; ret"); }
void vuln(void){ char b[64]; printf("say: "); fflush(stdout); gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Libcland64 =="); vuln(); return 0; }
