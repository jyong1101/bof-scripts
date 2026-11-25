/* Authorised coursework; localhost clone; dummy flag.
 * A login gate stands in front of the overflow. The credentials are literals in the
 * binary, so they are recoverable from .rodata - but only if the tool looks. Sending the
 * payload at the username prompt achieves nothing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/login.txt","r");
  if(!p){puts("win, but flags/login.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Logged in and over. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("note: "); fflush(stdout); gets(b); }
int main(void){
    char u[64], p[64];
    setvbuf(stdout,NULL,_IONBF,0);
    puts("== Members Only ==");
    printf("username: "); fflush(stdout);
    if (!fgets(u, sizeof u, stdin)) return 0;
    u[strcspn(u, "\r\n")] = 0;
    printf("password: "); fflush(stdout);
    if (!fgets(p, sizeof p, stdin)) return 0;
    p[strcspn(p, "\r\n")] = 0;
    if (strcmp(u, "operator") != 0 || strcmp(p, "sw0rdf1sh") != 0) {
        puts("access denied"); fflush(stdout); return 0;
    }
    puts("welcome, operator");
    vuln();
    puts("bye");
    return 0;
}
