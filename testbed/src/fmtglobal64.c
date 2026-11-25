/*
 * Authorised coursework; localhost clone; dummy flag.
 * The flag is a GLOBAL and nothing on the stack points at it: the address has to go in the
 * payload and be read with %s. 64-bit, so the address contains NUL bytes and must sit AFTER
 * the format - the lab's address-first layout cannot work here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
char flag[128];
int main(void)
{
    char buf[128];
    int fd = open("flags/fmtglobal64.txt", 0);
    if (fd < 0) { puts("flag file missing"); return 0; }
    read(fd, flag, 100); close(fd);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Echo service. Say something: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    printf("\n");
    return 0;
}
