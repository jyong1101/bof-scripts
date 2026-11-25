/*
 * Authorised coursework; localhost clone; NO FLAG - a negative.
 * A harmless `Name:` prompt, then a bounded echo loop: no overflow, no format bug, but an
 * executable stack and a printed buffer address. Nothing may report SOLVED here - it is the
 * negative for the later-prompt shellcode / ret2libc paths of rounds 31-33.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void)
{
    char name[32]; char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== ECHO DESK ==");
    printf("Name: "); if (!fgets(name, sizeof name, stdin)) return 0;
    printf("Hello, %s", name);
    printf("Scratch buffer at %p\n", (void *)buf);
    for (;;) {
        printf("Message: ");
        if (!fgets(buf, sizeof buf, stdin)) break;      /* bounded: no overflow */
        printf("You said: %s", buf);                    /* constant format: no bug */
        puts(buf);
    }
    return 0;
}
