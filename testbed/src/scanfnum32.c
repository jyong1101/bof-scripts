/* Authorised coursework; localhost clone; dummy flag.
 * A numeric prompt comes FIRST: scanf("%d") must be satisfied before the overflow is
 * reachable. A client that fires its payload at the first prompt never gets past it. */
#include <stdio.h>
#include <stdlib.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/scanfnum.txt","r");
  if(!p){puts("win, but flags/scanfnum.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Numeric gate passed. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; printf("now your message: "); fflush(stdout); gets(b); }
int main(void){
    int n = 0;
    setvbuf(stdout,NULL,_IONBF,0);
    puts("== NumGate ==");
    printf("how many bytes will you send? "); fflush(stdout);
    if (scanf("%d", &n) != 1) { puts("not a number"); return 0; }
    while (getchar() != '\n' && !feof(stdin)) { }    /* eat the rest of the line */
    printf("ok, %d\n", n); fflush(stdout);
    vuln();
    puts("bye");
    return 0;
}
