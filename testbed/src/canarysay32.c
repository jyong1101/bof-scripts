/*
 * Authorised coursework; localhost clone; dummy flag.
 * A forking canary service that prints its last line ("Received.") BEFORE the canary is
 * checked. The brute force watched that line, so every guess "survived": canary = 0x0 in one
 * second, then failure. glibc's own abort message is the real signal.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

static void win(void)
{
    char flag[128]; FILE *f = fopen("flags/canarysay32.txt", "r");
    if (!f) { dprintf(1, "win, but flags/canarysay32.txt missing\n"); return; }
    if (fgets(flag, sizeof(flag), f)) dprintf(1, "Canary brute-forced. %s\n", flag);
    fclose(f);
}

static void handle(void)
{
    char b[64];
    dprintf(1, "in: ");
    ssize_t n = read(0, b, 0x200);
    if (n < 0) return;
    dprintf(1, "Received.\n");          /* printed BEFORE the canary is checked */
}

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 20100;
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a = {0};
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    a.sin_family = AF_INET; a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(0x7f000001);          /* 127.0.0.1 only */
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) || listen(s, 32)) { perror("bind"); return 1; }
    signal(SIGCHLD, SIG_IGN);
    (void) win;                                      /* keep win() linked */
    for (;;) {
        int c = accept(s, 0, 0);
        if (c < 0) continue;
        if (fork() == 0) { dup2(c, 0); dup2(c, 1); dup2(c, 2); handle(); _exit(0); }
        close(c);
    }
}
