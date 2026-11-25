/*
 * Authorised coursework; localhost clone; dummy flag. A DOCUMENTED LIMIT, kept as a
 * test of the FAILURE REPORT: a format-string bug whose buffer is a global, so no address
 * can be planted and the %n write the guard needs is impossible with what the labs teach.
 * Nothing may report SOLVED; the run must end by saying why, and its `--goal dump` must work.
 */
#include <stdio.h>
#include <stdlib.h>
int target = 0;
char line[128];                       /* the format buffer is a GLOBAL, not on the stack */
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== ECHO VAULT ==");
    printf("Say something: ");
    if (!fgets(line, sizeof line, stdin)) return 0;
    printf(line);
    if (target == 0x1337) {
        char f[128]; FILE *fp = fopen("flags/fmtglobbuf32.txt", "r");
        if (fp && fgets(f, sizeof f, fp)) printf("Vault open: %s\n", f);
    } else puts("\nVault stays shut.");
    return 0;
}
