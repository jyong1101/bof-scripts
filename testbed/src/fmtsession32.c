/*
 * Authorised coursework; localhost clone; NO FLAG - a negative.
 * A real format-string bug, a guard that can never be satisfied, and a random 32-hex-digit
 * SESSION ID in every reply. The overflow attempts, the flood and fmtwrite.py each reported
 * the session id as the flag. A bare hex token the service prints without being exploited
 * is furniture; its SHAPE is learned from the reply to a harmless input.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* A real format-string bug and a writable guard - but the guard can never be satisfied,
   and the reply carries a 32-hex-digit SESSION ID. Nothing here is a flag. */
int target = 0;
volatile int never = 0;
int main(void)
{
    char buf[128]; unsigned char sid[16];
    setvbuf(stdout, NULL, _IONBF, 0);
    FILE *r = fopen("/dev/urandom", "r"); fread(sid, 1, 16, r); fclose(r);
    puts("== TICKET DESK ==");
    printf("Describe the problem: ");
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    printf(buf);
    printf("\nLogged. session=");
    for (int i = 0; i < 16; i++) printf("%02x", sid[i]);
    puts("");
    if (target == 0x1337 && never) puts("unreachable");
    return 0;
}
