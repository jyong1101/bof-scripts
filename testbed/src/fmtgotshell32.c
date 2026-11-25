/*
 * Authorised coursework; localhost clone; dummy flag.
 * GOT overwrite -> win(), where win() is system("/bin/sh"): the write succeeds silently and
 * the flag only appears if a command is typed into the shell afterwards.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void win(void) { system("/bin/sh"); }
int main(void)
{
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Feedback: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    puts("Thanks, bye.");
    return 0;
}
