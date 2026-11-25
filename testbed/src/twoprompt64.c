/*
 * Authorised coursework; localhost clone; dummy flag.
 * A harmless `Name:` prompt (bounded fgets) BEFORE the vulnerable `Message:` read; win() and
 * the offset are printed only after the first answer. No files are handed out.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ char f[128]; FILE*fp=fopen("flags/twoprompt64.txt","r"); if(!fp){puts("missing");exit(0);} if(fgets(f,sizeof f,fp)) printf("Mission complete: %s\n",f); fflush(stdout); exit(0);}
void vulnerable(void){
    char name[32]; char buffer[32];
    printf("Name: "); if(!fgets(name,sizeof name,stdin)) exit(0);
    printf("Hello, %.20s", name);
    printf("win():         %p\noffset to RIP: 72 bytes\nMessage: ", (void*)win);
    read(0, buffer, 128);
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); setvbuf(stdin,NULL,_IONBF,0); puts("=== GUESTBOOK ==="); vulnerable(); puts("Saved."); return 0; }
