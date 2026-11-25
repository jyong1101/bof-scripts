/*
 * Authorised coursework; localhost clone; dummy flag.
 *
 * ANTI-SCRIPT BOX built on a PROVEN-exploitable body (same vuln() as cyclic32, which the
 * suite already exploits). The only new thing is what sits in FRONT of the overflow:
 *   gate 1  arithmetic on fresh numbers   - "what is 37 + 58 ?"
 *   gate 2  nonce echo                    - a random token, sent back verbatim
 *   gate 3  too-fast rejection            - input under 150ms is treated as a bot
 * A hardcoded script dies at gate 1; each gate must be read and answered live.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include "vuln_compat.h"

static long now_ms(void)
{
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}
void win(void)
{
    char flag[128]; FILE *f = fopen("flags/gated.txt", "r");
    if (!f) { puts("win, but flags/gated.txt missing"); return; }
    if (fgets(flag, sizeof(flag), f)) printf("Every gate passed. %s\n", flag);
    fclose(f); fflush(stdout); exit(0);
}
void vuln(void)
{
    char buf[64];
    printf("message: "); fflush(stdout);
    gets(buf);
}
int main(void)
{
    char line[128], nonce[9];
    int a, b;
    long t0;
    setvbuf(stdout, NULL, _IONBF, 0);
    srand((unsigned)(time(NULL) ^ (getpid() << 16)));
    a = 10 + rand() % 90; b = 10 + rand() % 90;
    for (int i = 0; i < 8; i++) nonce[i] = "0123456789abcdef"[rand() % 16];
    nonce[8] = 0;

    puts("== Gated Vault ==");
    printf("[gate 1] what is %d + %d ?\n", a, b); fflush(stdout);
    t0 = now_ms();
    if (!fgets(line, sizeof(line), stdin)) return 0;
    if (now_ms() - t0 < 150) { puts("too fast - automated client rejected"); fflush(stdout); return 0; }
    if (atoi(line) != a + b) { puts("wrong answer"); fflush(stdout); return 0; }

    printf("[gate 2] echo this token back: %s\n", nonce); fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return 0;
    line[strcspn(line, "\r\n")] = 0;
    if (strcmp(line, nonce) != 0) { puts("bad token"); fflush(stdout); return 0; }

    puts("[gate 3] vault open.");
    vuln();
    return 0;
}
