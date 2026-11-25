/* Authorised coursework; localhost clone; dummy flag.
 * ret2shellcode where the input function EATS SHELLCODE BYTES. scanf("%s") stops at any
 * whitespace - including 0x0b, and the standard execve shellcode contains exactly that
 * byte (`push 0xb; pop eax` / `mov al, 0xb`). The textbook payload is silently truncated
 * in the middle of the shellcode. Same body as the proven relay clone; only the read
 * changed. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

__attribute__((used, noinline)) void trampoline(void)
{
    __asm__ volatile("jmp *%esp");
}

void relay(void)
{
    char buf[200];
    puts("Relay node. Transmit (one word):");
    scanf("%s", buf);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    relay();
    puts("end of transmission");
    return 0;
}
