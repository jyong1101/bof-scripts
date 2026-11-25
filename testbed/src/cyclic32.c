/*
 * Authorised coursework; localhost clone; dummy flag.
 * RATE-LIMITED service: 1.2s penalty per connection, so a 127-attempt offset scan is
 * hopeless. It does leak the saved return address after the overflow, so a single
 * cyclic pattern reveals the offset in ONE connection.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vuln_compat.h"
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/cyclic.txt", "r");
    if (!f) { puts("win, but flags/cyclic.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Unlocked. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void)
{
    char buf[64];
    printf("Say something: "); fflush(stdout);
    gets(buf);
    printf("saved ret was: %p\n", __builtin_return_address(0));
    fflush(stdout);
}
int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    usleep(1200000);                       /* rate limit: scanning is not viable */
    puts("== SlowGate ==");
    vuln();
    return 0;
}
