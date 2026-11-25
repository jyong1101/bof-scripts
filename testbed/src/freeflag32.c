/*
 * Authorised coursework; localhost clone; dummy flag.
 * The mirror image of hintreply32: no bug, and the REAL flag is printed for any input
 * ("connect and type anything"). The tools cannot tell this from an example, so they must
 * not say SOLVED - but the run has to end with the candidate on a line of its own.
 */
#include <stdio.h>
#include <string.h>
/* The mirror image: the REAL flag is printed for any input. "Connect and type anything." */
int main(void)
{
    char buf[64], f[96] = {0};
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== WARM-UP ==");
    printf("Say hello: ");
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    FILE *fp = fopen("flags/freeflag32.txt", "r"); if (fp) { fgets(f, sizeof f, fp); fclose(fp); }
    printf("Welcome! Here is your flag: %s", f);
    return 0;
}
