/*
 * Authorised coursework; localhost clone; dummy flag.
 * Live 5003 (Echo32) with a harmless `Name:` prompt BEFORE the vulnerable read, and a second
 * array in the frame: the overflow is at read #2 and its offset (164) is the SECOND one the
 * frame analysis lists. Shellcode sent at the first prompt with the first offset fails.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
__attribute__((used, noinline)) void jump_to_stack(void) { __asm__ volatile("jmp *%esp"); }
void vulnerable(void)
{
    char name[24]; char buf[128];
    printf("Name: "); fflush(stdout);
    if (!fgets(name, sizeof name, stdin)) return;
    printf("Hello, %.20s", name);
    puts("Enter a message:"); fflush(stdout);
    read(0, buf, 0x200);
    puts("Message received."); fflush(stdout);
}
int main(void) { setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stdin, NULL, _IONBF, 0); vulnerable(); puts("bye"); return 0; }
