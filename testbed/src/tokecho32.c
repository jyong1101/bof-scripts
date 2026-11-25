/*
 * Authorised coursework; localhost clone; NO FLAG - a negative.
 * A "command parser" with no bug: a bounded read, then every word of the input printed on
 * its own line. That put `===SHELL===` alone on a line and the tools reported "shell
 * confirmed" / SOLVED in 8 s. Evidence of a shell is now a COMPUTED value (flags.PROOF_CMD).
 */
#include <stdio.h>
#include <string.h>
/* NO BUG. A "command parser": bounded read, then every word printed on its own line. */
int main(void)
{
    char buf[512];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Parser ready. Scratch buffer at %p\n", (void *)buf);
    for (;;) {
        printf("> ");
        if (!fgets(buf, sizeof buf, stdin)) break;
        puts("tokens:");
        for (char *t = strtok(buf, " ;\t\n"); t; t = strtok(NULL, " ;\t\n")) puts(t);
    }
    return 0;
}
