/*
 * Authorised coursework; localhost clone; dummy flag.
 * NEGATIVE: there is NO vulnerability here. It prints a stack address, has an executable
 * stack, and echoes every line back - bounded read, constant format. A tool that confirms
 * a shell by finding its own marker text in the reply reports SOLVED on this.
 */
#include <stdio.h>
#include <string.h>
int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Scratch buffer at %p\n", (void *)buf);
    for (;;) {
        printf("> ");
        if (!fgets(buf, sizeof buf, stdin)) break;      /* bounded: no overflow */
        printf("You said: %s", buf);                    /* constant format: no fmt bug */
    }
    return 0;
}
