/* Authorised coursework; localhost clone; dummy flag.
 * strncpy with the WRONG size: the bound is the size of the source, not the destination,
 * so a "safe" function overflows anyway. The read itself is bounded; only the copy is
 * wrong. Copy lives in its own frame so the return address is reachable. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void win(void){ char f[128]; FILE*p=fopen("flags/strncpy.txt","r");
  if(!p){puts("win, but flags/strncpy.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Wrong bound. %s\n",f); fclose(p); fflush(stdout); exit(0); }
void copy_in(const char *src, size_t n){ char small[64]; strncpy(small, src, n); }
int main(void){
    char big[256];
    setvbuf(stdout,NULL,_IONBF,0);
    puts("== SafeCopy ==");
    printf("text: "); fflush(stdout);
    if (!fgets(big, sizeof big, stdin)) return 0;
    big[strcspn(big, "\r\n")] = 0;
    copy_in(big, sizeof big);          /* BUG: should be sizeof small */
    puts("bye");
    return 0;
}
