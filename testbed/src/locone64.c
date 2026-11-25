/*
 * Authorised coursework; localhost clone; dummy flag.
 * `level == 1` where level and buf are SEPARATE locals, not struct members: the compiler,
 * not the language, decides the gap (28 bytes here for a 20-byte buffer). From source alone
 * the offset is unknowable, so the value has to be sprayed across the words after the buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
static void show(const char *p, const char *m)
{
    char flag[128]; FILE *f = fopen(p, "r");
    if (!f) { printf("win, but %s missing\n", p); return; }
    if (fgets(flag, sizeof flag, f)) printf("%s %s\n", m, flag);
    fclose(f); fflush(stdout);
}
int main(void)
{
    int level = 0; char buf[20];
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Input: "); gets(buf);               /* <-- overflow into level */
    if (level == 1) show("flags/locone64.txt", "Level one.");
    else printf("level=%d\n", level);
    return 0;
}
