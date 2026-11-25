/*
 * Authorised coursework; localhost clone; dummy flag.
 * Lab 10 'Injecting code' as taught: NOP sled + shellcode IN the buffer, return to the
 * buffer's address. No jmp esp gadget; under ASLR the address is the one the service prints.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void vuln(void)
{
    char buf[128];
    printf("Your buffer is at %p\n", (void *)buf);
    printf("Data: "); gets(buf);                /* <-- overflow, executable stack */
}
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
