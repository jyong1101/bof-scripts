/*
 * Authorised coursework; localhost clone; dummy flag.
 * OUT OF BAND, in the professor's own format: live challenge 5002 ("STACK LAB") printed
 * `buffer: / saved RIP: / win(): / offset to RIP:` in its banner. This is the same service
 * with that block REMOVED - as if it had been moved onto the question paper. No binary is
 * handed out (5002 gave none), so the address and the offset exist only in the notes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/paperlab64.txt", "r");
    if (!f) { puts("win, but flags/paperlab64.txt missing"); exit(0); }
    if (fgets(flag, sizeof flag, f)) printf("Mission complete: %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vulnerable(void)
{
    char buffer[32];
    read(0, buffer, 128);                       /* <-- overflow; offset to RIP is 40 */
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("\n=== STACK LAB: Watch a buffer overflow happen ===");
    puts("The details you need are on your question paper.\n");
    printf("Mission: replace the saved RIP with win()\n> ");
    vulnerable();
    puts("Returned normally. Nothing happened.");
    return 0;
}
