/*
 * Authorised coursework; localhost clone; dummy flag.
 * ret2libc32 with a harmless `Name:` prompt BEFORE the vulnerable gets(), and a second array
 * in the frame (offset 100, the frame's second candidate). Both ret2libc stages have to
 * answer the name prompt first.
 */
#include <stdio.h>
#include <stdlib.h>
char *gets(char *);
void vuln(void)
{
    char name[24]; char b[64];
    printf("Name: "); fflush(stdout);
    if (!fgets(name, sizeof name, stdin)) exit(0);
    printf("Hello, %.20s", name);
    printf("say: "); fflush(stdout);
    gets(b);
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stdin, NULL, _IONBF, 0);
    puts("== Libcland 2 ==");
    vuln();
    return 0;
}
