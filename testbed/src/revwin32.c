/*
 * Authorised coursework; localhost clone; dummy flag.
 * ANTI-SCRIPT: ret2win where win() prints the flag REVERSED. The exploit succeeds and a
 * matcher looking for SIT{ says it failed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; int i; FILE *f = fopen("flags/revwin32.txt", "r");
    if (!f) { puts("flag file missing"); exit(0); }
    fgets(flag, sizeof flag, f); fclose(f); flag[strcspn(flag, "\n")] = 0;
    printf("Well done! Reward, reversed: ");
    for (i = strlen(flag) - 1; i >= 0; i--) putchar(flag[i]);
    printf("\n"); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
