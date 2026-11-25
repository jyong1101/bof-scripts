/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * COMPOSITION of two service shapes that each already work alone:
 *   1. a password gate  (as login32)   - credentials live in .rodata
 *   2. a safe first read (as tworead32) - the OVERFLOW is on the second read
 * So the payload must arrive at the FOURTH prompt, after three harmless lines. Each
 * walker handles its own shape; this only falls if they cannot chain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/loginread.txt","r");
  if(!p){puts("win, but flags/loginread.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Login and second read. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("Enter your message: "); fflush(stdout); gets(b); }
int main(void)
{
    char u[64], p[64], name[32];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== Staff Portal ==");
    printf("username: "); fflush(stdout);
    if (!fgets(u, sizeof u, stdin)) return 0;
    u[strcspn(u, "\r\n")] = 0;
    printf("password: "); fflush(stdout);
    if (!fgets(p, sizeof p, stdin)) return 0;
    p[strcspn(p, "\r\n")] = 0;
    if (strcmp(u, "curator") != 0 || strcmp(p, "p1nk-f1sh") != 0) {
        puts("access denied"); fflush(stdout); return 0;
    }
    puts("welcome, curator");
    printf("Enter your name: "); fflush(stdout);
    if (!fgets(name, sizeof name, stdin)) return 0;
    name[strcspn(name, "\r\n")] = 0;
    printf("Hello, %s.\n", name);
    vuln();
    puts("bye");
    return 0;
}
