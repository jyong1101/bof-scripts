/*
 * Authorised coursework; localhost clone; dummy flag.
 * bufleak32 (the lab's NOP sled + shellcode at a printed buffer address) with a harmless
 * `Name:` prompt first: the address is printed only AFTER the first answer, and the offset
 * (164) is the frame's second candidate.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char *gets(char *);
void vuln(void)
{
    char name[24]; char buf[128];
    printf("Name: "); if (!fgets(name, sizeof name, stdin)) exit(0);
    printf("Hello, %.20s", name);
    printf("Your buffer is at %p\n", (void *)buf);
    printf("Data: "); gets(buf);
}
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stdin, NULL, _IONBF, 0); vuln(); puts("bye"); return 0; }
