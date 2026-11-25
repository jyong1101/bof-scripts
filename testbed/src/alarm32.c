/* Authorised coursework; localhost clone; dummy flag.
 * alarm(3): the process dies 3s after connect. A slow per-connection scan never finishes,
 * so the offset has to come from the binary or from a single cyclic probe. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/alarm.txt","r");
  if(!p){puts("win, but flags/alarm.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Beat the clock. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("quick: "); fflush(stdout); gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); alarm(3); puts("== Alarm =="); vuln(); return 0; }
