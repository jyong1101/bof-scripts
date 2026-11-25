/*
 * Authorised coursework; localhost clone; dummy flag.
 * 64-bit ret2win that requires 16-byte STACK ALIGNMENT, the classic `movaps` crash.
 * Returning straight into win() leaves RSP misaligned; you must return into a bare
 * `ret` gadget first (one extra 8-byte slot) to realign.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "vuln_compat.h"
void win(void)
{
    /* Alignment is judged from the FRAME POINTER, which is the same on every compiler:
     * a properly called function has rsp = 16n+8 on entry, so after `push rbp` the frame
     * pointer is 16n. The first version read rsp AFTER the prologue's `sub rsp,N` and
     * assumed gcc 15's N; rebuilt with gcc 12 the check said the opposite of what libc
     * actually requires, and no payload could satisfy both - a broken fixture, found by
     * rebuilding on Debian 12. */
    uintptr_t fp = (uintptr_t)__builtin_frame_address(0); char flag[128]; FILE *f;
    if (fp % 16 != 0) { puts("crash: stack misaligned (movaps would fault)"); fflush(stdout); return; }
    f = fopen("flags/align.txt", "r");
    if (!f) { puts("win, but flags/align.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Aligned. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void greet(void){ char b[40]; printf("Name: "); fflush(stdout); gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== AlignGate =="); greet(); puts("bye"); return 0; }
