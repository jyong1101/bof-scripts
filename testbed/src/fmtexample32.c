/*
 * Authorised coursework; localhost clone; NO FLAG - a negative.
 * A REAL format-string bug with nothing to read or write, whose reply carries a flag-shaped
 * example. The format engine reported the example as the flag ("a pointer on the stack")
 * in 4 s. hintreply32's twin for the tools that do not go through auto_pwn.
 */
#include <stdio.h>
#include <string.h>
/* A real format-string bug - but nothing worth reading or writing; the reply carries an EXAMPLE. */
int main(void)
{
    char buf[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("== FEEDBACK BOX ==");
    printf("Your comment: ");
    if (!fgets(buf, sizeof buf, stdin)) return 0;
    printf(buf);
    puts("\nThanks. (Reminder: flags look like SIT{example_flag_here}.)");
    return 0;
}
