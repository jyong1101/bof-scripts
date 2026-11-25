/*
 * Authorised coursework; localhost clone; dummy flag.
 * bufleak32 with a 16-byte buffer: the shellcode does not FIT before the return address, so
 * it has to go after it, and the return target is buffer + offset + 4.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void vuln(void)
{
    char buf[16];
    printf("Your buffer is at %p\n", (void *)buf);
    printf("Data: "); gets(buf);                /* <-- overflow, executable stack */
}
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
