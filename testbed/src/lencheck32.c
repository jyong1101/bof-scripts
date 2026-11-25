/*
 * Authorised coursework; localhost clone; NO FLAG - a negative.
 * No bug: a bounded read and a LENGTH CHECK that refuses long input with a message. The
 * crash-based offset search saw the clean ending vanish at 41 bytes and the diagnosis said
 * "CRASHES the service - a stack overflow". A refusal prints something; a crash does not.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* NO BUG. A bounded read and a LENGTH CHECK: long input is refused politely, nothing crashes. */
int main(void)
{
    char buf[512];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== NAME TAG PRINTER ==");
    printf("Name (max 40): ");
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    buf[strcspn(buf, "\n")] = 0;
    if (strlen(buf) > 40) { puts("Too long - rejected."); return 1; }
    printf("Printing tag for %s\nDone.\n", buf);
    return 0;
}
