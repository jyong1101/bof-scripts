/*
 * Authorised coursework; localhost clone; dummy flag.
 * Live 5002 with the `offset to RIP` line REMOVED and a 264-byte buffer: the distance must be
 * computed as saved RIP - buffer (280). A sweep of small offsets never reaches it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ char f[128]; FILE*fp=fopen("flags/labcalc64.txt","r"); if(!fp){puts("missing");exit(0);} if(fgets(f,sizeof f,fp)) printf("Mission complete: %s\n",f); fflush(stdout); exit(0);}
void vulnerable(void){
    char buffer[264];
    printf("buffer:        %p\n", (void*)buffer);
    printf("saved RIP:     %p\n", (void*)((char*)__builtin_frame_address(0)+8));
    printf("win():         %p\n\n", (void*)win);
    printf("Mission: replace the saved RIP with win()\n> ");
    read(0, buffer, 400);
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); puts("\n=== STACK LAB 2: work out the distance yourself ==="); vulnerable(); puts("Returned normally."); return 0; }
