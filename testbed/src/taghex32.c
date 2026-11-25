/*
 * Authorised coursework; localhost clone; dummy flag.
 * A real ret2win (offset 84) that prints the first 4 bytes of the input as a hex "tag". To
 * the cyclic-pattern search that looks like a leaked return address at pattern offset 0:
 * it announced "use --offset 0", tried only that, and gave up.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* A real ret2win - and the service prints the first 4 bytes of the input as a hex "tag",
   which looks exactly like a leaked return address holding the start of a cyclic pattern. */
void win(void){ char f[128]; FILE*fp=fopen("flags/taghex32.txt","r"); if(!fp){puts("missing");exit(0);} if(fgets(f,sizeof f,fp)) printf("Unlocked: %s\n",f); fflush(stdout); exit(0);}
void vuln(void){ char buf[72]; unsigned int tag; printf("win() is at %p\nLabel: ", (void*)win); read(0, buf, 300); memcpy(&tag, buf, 4); printf("tag: 0x%08x\n", tag); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== LABEL MAKER =="); vuln(); puts("Printed."); return 0; }
