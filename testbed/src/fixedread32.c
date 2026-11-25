/* Authorised coursework; localhost clone; dummy flag.
 * read(0, buf, 256): no newline semantics at all. The payload is taken as raw bytes, so a
 * client that always appends '\n' still works, but one that waits for a prompt-per-line
 * does not. NUL bytes pass through untouched. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ char f[128]; FILE*p=fopen("flags/fixedread.txt","r");
  if(!p){puts("win, but flags/fixedread.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Raw read. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("send bytes: "); fflush(stdout); read(0,b,256); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== FixedRead =="); vuln(); puts("bye"); return 0; }
