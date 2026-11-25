/* Authorised coursework; localhost clone; dummy flag.
 * The service REJECTS the letter 'A', and the read is BOUNDED, so the filter actually
 * bites: the overflow only happens on the strcpy AFTER the check passes. Every payload
 * this toolkit builds pads with 'A', so the filler must be chosen, not assumed.
 *
 * (First version used gets(tmp) and was bypassable by accident - the overflow corrupted
 * the return address before strchr ran, so the early `return` already went to win().
 * A filter check is only a filter if nothing has overflowed yet when it runs.) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vuln_compat.h"
void win(void){ char f[128]; FILE*p=fopen("flags/filtered.txt","r");
  if(!p){puts("win, but flags/filtered.txt missing");return;}
  if(fgets(f,sizeof f,p))printf("Filter dodged. %s\n",f); fclose(p); fflush(stdout); exit(0); }
/* The vulnerable copy lives in its OWN small frame, so the return address is reachable
 * within the bounded read. (With tmp[512] in the same frame the needed offset was ~588,
 * past the fgets bound - unexploitable by construction, which is a clone bug, not a
 * defence.) */
void copy_in(const char *src)
{
    char b[64];
    strcpy(b, src);
}
void vuln(void){
    char tmp[256];
    printf("message (no capital A allowed): "); fflush(stdout);
    if (!fgets(tmp, sizeof tmp, stdin)) return;   /* BOUNDED: no overflow yet */
    tmp[strcspn(tmp, "\r\n")] = 0;
    if (strchr(tmp, 'A')) { puts("rejected: capital A detected"); fflush(stdout); return; }
    copy_in(tmp);
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("== Filter =="); vuln(); puts("bye"); return 0; }
