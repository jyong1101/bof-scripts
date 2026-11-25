/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * Reproduces live 5001: adjacent struct field, guard constant present ONLY in the
 * source (the student gets chall.c, no binary). auto_pwn used to write 0 silently.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct player { char name[32]; unsigned int access_code; };

static void win(void)
{
    char flag[128];
    FILE *f = fopen("flags/varsrc.txt", "r");
    if (!f) { puts("win, but flags/varsrc.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Access granted. %s\n", flag);
    fclose(f);
}

int main(void)
{
    struct player p;
    setvbuf(stdout, NULL, _IONBF, 0);
    memset(&p, 0, sizeof(p));
    puts("=== Rookie Access Terminal ===");
    printf("Enter your name:\n");
    if (read(STDIN_FILENO, p.name, 64) <= 0) return 0;
    printf("Hello, %.32s!\n", p.name);
    if (p.access_code == 0x1337c0de) win();
    else printf("Access denied. Code: 0x%08x\n", p.access_code);
    return 0;
}
