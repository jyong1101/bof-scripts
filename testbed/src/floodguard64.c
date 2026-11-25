/*
 * Authorised coursework; localhost clone; dummy flag.
 * A guard compared with a secret drawn at RUN TIME and never printed. It looks like the
 * documented limit - but the overflow reaches BOTH sides, so one byte repeated makes them
 * equal. Was found only by accident, 73 s in, under the strcmp label; now a deliberate
 * first attempt.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void show(const char *p){ char f[128]; FILE*fp=fopen(p,"r"); if(!fp){puts("missing");exit(0);} if(fgets(f,sizeof f,fp)) printf("Flag: %s\n",f); fflush(stdout); }

/* LIMIT: a run-time guard that is never printed */
int main(void){ unsigned int secret; char buf[32]; unsigned int key=0; setvbuf(stdout,NULL,_IONBF,0);
  FILE*r=fopen("/dev/urandom","r"); fread(&secret,4,1,r); fclose(r);
  puts("== VAULT =="); printf("Code: "); read(0,buf,64);
  if(key==secret) show("flags/floodguard64.txt"); else puts("Wrong code."); return 0; }
