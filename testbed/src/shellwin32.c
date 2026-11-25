/*
 * Authorised coursework; localhost clone; dummy flag.
 * win() does NOT print the flag: it runs system("/bin/sh"). Landing there prints one line and
 * waits - a tool that only reads the reply reports a miss on a perfectly good exploit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void win(void) { puts("Spawning shell..."); fflush(stdout); system("/bin/sh"); exit(0); }
void vuln(void) { char buf[48]; printf("Say: "); gets(buf); }
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
