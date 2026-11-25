/*
 * Authorised coursework; localhost clone; NO FLAG - a negative.
 * No bug. The banner is clean; the REPLY to anything shows a flag-shaped example
 * ("Flags look like SIT{example_flag_here}"). It was reported as the flag, SOLVED, in 3 s.
 * What a harmless input gets back is not a flag an exploit earned.
 */
#include <stdio.h>
#include <string.h>
/* NO BUG. The banner is clean; the REPLY to any wrong answer shows a flag-shaped example. */
int main(void)
{
    char buf[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== SUBMISSION DESK ==");
    printf("Submit your flag: ");
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    puts("Wrong. Flags look like SIT{example_flag_here} - try again later.");
    return 0;
}
