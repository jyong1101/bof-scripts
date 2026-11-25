/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: read(0, buf, 48) stops exactly after the saved return address (offset 40).
 * win() runs system(), which faults on a misaligned stack, and there is NO ROOM for the
 * usual extra `ret` gadget. Alignment has to come from entering win() past its `push rbp`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void win(void) { puts("Spawning shell..."); fflush(stdout); system("/bin/sh"); exit(0); }
void vuln(void) { char buf[32]; printf("Say (48 bytes max): "); read(0, buf, 48); }
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
