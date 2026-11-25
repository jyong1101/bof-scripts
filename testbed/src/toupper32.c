/* Authorised coursework; localhost clone; dummy flag.
 * Input is upper-cased before the copy. Address bytes in the a-f range get mangled
 * (0x61-0x66 -> 0x41-0x46), so only a win address whose bytes survive toupper() works.
 * A tool must notice the transform rather than wonder why a correct payload fails. */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/toupper.txt","r");
  if(!p){puts("win, but flags/toupper.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Survived the transform. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){
    char tmp[512], b[64];
    printf("SHOUT: "); fflush(stdout);
    gets(tmp);
    for (size_t i = 0; i < strlen(tmp); i++) tmp[i] = (char)toupper((unsigned char)tmp[i]);
    strcpy(b, tmp);
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Shout =="); vuln(); puts("bye"); return 0; }
