/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: the exploit is plain ret2win, but win() prints the flag as one HEX string.
 * A flag matcher that reads a long hex run as little-endian stack words reports a confident,
 * wrong flag (`borp{TIS...`); one that only knows SIT{ reports a failure on a success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; int i; FILE *f = fopen("flags/hexwin32.txt", "r");
    if (!f) { puts("flag file missing"); exit(0); }
    fgets(flag, sizeof flag, f); fclose(f); flag[strcspn(flag, "\n")] = 0;
    printf("Well done! Your reward (hex): ");
    for (i = 0; flag[i]; i++) printf("%02x", (unsigned char)flag[i]);
    printf("\n"); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
