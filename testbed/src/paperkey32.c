/*
 * Authorised coursework; localhost clone; dummy flag.
 * OUT OF BAND: win(key) where the key is read from a file and never shown. The paper gives
 * it as a SUM ("the key is 0x1000 + 0x337"), so being told is not enough - the note has to
 * be evaluated.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vuln_compat.h"
static void show(const char *p, const char *m)
{
    char flag[128]; FILE *f = fopen(p, "r");
    if (!f) { printf("win, but %s missing\n", p); return; }
    if (fgets(flag, sizeof flag, f)) printf("%s %s\n", m, flag);
    fclose(f); fflush(stdout);
}
static unsigned long secret_num(const char *p)
{
    char b[64]; FILE *f = fopen(p, "r");
    if (!f) { puts("secret file missing"); exit(0); }
    fgets(b, sizeof b, f); fclose(f);
    return strtoul(b, NULL, 0);
}
unsigned int key;
void win(unsigned int k)
{
    if (k != key) { puts("wrong key"); exit(0); }
    show("flags/paperkey32.txt", "Keyed."); exit(0);
}
void vuln(void) { char buf[40]; printf("Data: "); gets(buf); }
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    key = (unsigned int)secret_num("flags/paperkey_secret.txt");
    puts("The key for today is on your question paper.");
    vuln(); puts("bye");
    return 0;
}
