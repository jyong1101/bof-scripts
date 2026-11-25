/* Authorised coursework; localhost clone; dummy flag.
 * TWO reads. The first is bounded and harmless (a name); the SECOND is the overflow.
 * A client that fires its payload at the first prompt wastes it: 31 bytes are swallowed
 * by the safe read and the rest arrives misaligned. Very common lab layout. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/tworead.txt","r");
  if(!p){puts("win, but flags/tworead.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Second read was the one. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("Enter your message: "); fflush(stdout); gets(b); }
int main(void){
    char name[32];
    setvbuf(stdout,NULL,_IONBF,0);
    puts("== Guestbook ==");
    printf("Enter your name: "); fflush(stdout);
    if (!fgets(name, sizeof name, stdin)) return 0;
    name[strcspn(name, "\r\n")] = 0;
    printf("Hello, %s.\n", name);
    vuln();
    puts("bye");
    return 0;
}
