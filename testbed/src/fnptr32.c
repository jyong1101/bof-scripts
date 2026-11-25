/* Authorised coursework; localhost clone; dummy flag.
 * Adjacent-variable overwrite where the neighbour is a FUNCTION POINTER, not a guard
 * value: there is no magic constant to find, the value to write is win()'s address, and
 * the saved return address is never touched. */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void safe(void){ puts("handler: nothing to see here"); }
void win(void){ char f[128]; FILE*p=fopen("flags/fnptr.txt","r");
  if(!p){puts("win, but flags/fnptr.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Pointer redirected. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){
    struct { char buf[64]; void (*handler)(void); } s;
    s.handler = safe;
    printf("name: "); fflush(stdout);
    gets(s.buf);
    s.handler();
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Handler =="); vuln(); puts("bye"); return 0; }
