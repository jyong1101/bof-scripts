/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * Reproduces the LIVE Echo32 I/O shape that broke verify.py:
 *   - prints its own chatter ("Message received.") AFTER reading
 *   - does NOT echo the payload back
 * verify.py's leak extraction assumed the response began with the puts() leak, so the
 * chatter length (18 bytes) was added to every address comparison and the reported
 * shift was wrong by exactly that much (live: -0x10 reported as +0x2).
 * Build -DPAD for the shifted "downloaded" build.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef PAD
__attribute__((used, noinline)) void build_pad(void) { __asm__ volatile(".fill 16,1,0x90"); }
#endif

__attribute__((used, noinline)) void trampoline(void) { __asm__ volatile("jmp *%esp"); }

void vulnerable(void)
{
    char buf[128];
    puts("Welcome to ChattyEcho. Enter a message:");
    fflush(stdout);
    read(0, buf, 0x200);
    puts("Message received.");        /* chatter, and NO echo of the payload */
    fflush(stdout);
}

int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vulnerable(); puts("bye"); return 0; }
