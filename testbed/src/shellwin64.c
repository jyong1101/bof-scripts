/*
 * Authorised coursework; localhost clone; dummy flag.
 * shellwin32 on 64-bit: system() faults on a misaligned stack, so the correct offset must be
 * retried through a bare `ret` BEFORE sweeping other offsets, or the budget runs out.
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
