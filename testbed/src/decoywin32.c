/* Authorised coursework; localhost clone; dummy flag.
 * TWO win-like symbols. `win_check` looks right by name but refuses without a password;
 * `winner` is the real one. A tool that picks the first win-like symbol and stops fails. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win_check(void){ puts("win_check: refused (needs the admin password)"); fflush(stdout); }
void winner(void){ char f[128]; FILE*p=fopen("flags/decoy.txt","r");
  if(!p){puts("win, but flags/decoy.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Real winner. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("name: "); fflush(stdout); gets(b); }
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Decoy =="); vuln(); puts("bye"); return 0; }
