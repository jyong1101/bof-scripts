/* Authorised coursework; localhost clone; dummy flag.
 * The greeting is different on every connection. Anything that keys off exact banner text,
 * or caches a banner between attempts, breaks here. The overflow itself is ordinary. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "vuln_compat.h"
static const char *GREET[] = {"Welcome","Greetings","Hello there","Salutations","Ahoy","Good day"};
void win(void){ char f[128]; FILE*p=fopen("flags/randbanner.txt","r");
  if(!p){puts("win, but flags/randbanner.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Banner-independent. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void vuln(void){ char b[64]; gets(b); }
int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    printf("%s, visitor #%d\n", GREET[rand() % 6], rand() % 9000 + 1000);
    printf("%s: ", (rand() % 2) ? "input" : "data"); fflush(stdout);
    vuln();
    puts("bye");
    return 0;
}
