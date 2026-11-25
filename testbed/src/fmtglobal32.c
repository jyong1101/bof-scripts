/*
 * Authorised coursework; localhost clone; dummy flag.
 * fmtglobal64 on 32-bit: flag in a global, address in the payload, read with %s.
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
    int fd = open("flags/fmtglobal32.txt", 0);
    if (fd < 0) { puts("flag file missing"); return 0; }
    read(fd, flag, 100); close(fd);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Echo service. Say something: "); fgets(buf, sizeof buf, stdin);
    printf(buf);                                /* <-- format-string bug */
    printf("\n");
    return 0;
}
