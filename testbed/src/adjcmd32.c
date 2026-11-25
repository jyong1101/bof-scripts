/*
 * Authorised coursework; localhost clone; dummy flag.
 * The neighbour is a COMMAND: system(cmd) runs after the read, cmd starts as "date". There is
 * no comparison anywhere - the value to write is a shell command of your choosing.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
int main(void)
{
    struct { char buf[32]; char cmd[32]; } s;
    setvbuf(stdout, NULL, _IONBF, 0);
    strcpy(s.cmd, "date");
    printf("Name for the log: "); gets(s.buf);  /* <-- overflow into cmd */
    printf("Logging %s at:\n", s.buf); fflush(stdout);
    system(s.cmd);
    return 0;
}
