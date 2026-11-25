/*
 * Authorised coursework; localhost clone; dummy flag.
 * OUT OF BAND + a harmless prompt: nothing useful is printed, a `Name:` prompt comes first,
 * and a 32-byte name sits between the 200-byte buffer and the return address (offset 248 =
 * size + 48). The paper may give the exact offset, or only "buffer is 200 bytes".
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ char f[128]; FILE*fp=fopen("flags/paperquiet64.txt","r"); if(!fp){puts("missing");exit(0);} if(fgets(f,sizeof f,fp)) printf("Unlocked: %s\n",f); fflush(stdout); exit(0);}
void vulnerable(void){
    char name[32]; char buffer[200];
    printf("Name: "); if(!fgets(name,sizeof name,stdin)) exit(0);
    printf("Hello, %.20s", name);
    printf("Message: "); read(0, buffer, 400);
}
int main(void){ setvbuf(stdout,NULL,_IONBF,0); setvbuf(stdin,NULL,_IONBF,0); puts("=== GUESTBOOK 3 ==="); puts("Details are on your question paper."); vulnerable(); puts("Saved."); return 0; }
