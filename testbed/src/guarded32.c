/* NOT BUILT - kept as documentation only.
 * This clone is not exploitable as written: the compiler's frame padding puts the
 * overflow somewhere harmless, so it tested nothing. `gated32` replaces it, built on
 * cyclic32's proven-exploitable body. Lesson: verify a clone can be exploited BY HAND
 * before using it to judge a tool. */
/* Authorised coursework; localhost clone; dummy flag.
 *
 * An ANTI-SCRIPT BOX. The overflow is ordinary; the defences sit in front of it:
 *   1. arithmetic gate  - "what is 37 + 58?" with fresh numbers per connection
 *   2. nonce echo       - a random token that must be sent back verbatim
 *   3. too-fast check   - input arriving in under 150ms is rejected as automated
 * A hardcoded script dies at gate 1. Each gate must be read and answered live.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "vuln_compat.h"

static long now_ms(void)
{
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/guarded.txt", "r");
    if (!f) { puts("win, but flags/guarded.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Past every gate. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
int main(void)
{
    char line[256], buf[64], nonce[9];
    int a, b;
    long t0;
    unsigned seed;
    setvbuf(stdout, NULL, _IONBF, 0);
    seed = (unsigned)(time(NULL) ^ (getpid() << 16));
    srand(seed);
    a = 10 + rand() % 90; b = 10 + rand() % 90;
    for (int i = 0; i < 8; i++) nonce[i] = "0123456789abcdef"[rand() % 16];
    nonce[8] = 0;

    puts("== Guarded Vault ==");
    printf("[gate 1] what is %d + %d ?\n", a, b); fflush(stdout);
    t0 = now_ms();
    if (!fgets(line, sizeof(line), stdin)) return 0;
    if (now_ms() - t0 < 150) { puts("too fast - automated client rejected"); fflush(stdout); return 0; }
    if (atoi(line) != a + b) { puts("wrong answer"); fflush(stdout); return 0; }

    printf("[gate 2] echo this token back: %s\n", nonce); fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return 0;
    line[strcspn(line, "\r\n")] = 0;
    if (strcmp(line, nonce) != 0) { puts("bad token"); fflush(stdout); return 0; }

    printf("[gate 3] vault open. message: "); fflush(stdout);
    vuln_gets(buf);
    puts("bye");
    return 0;
}
