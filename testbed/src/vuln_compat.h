/*
 * vuln_compat.h - portable classic gets()
 *
 * glibc >= 2.34 removed gets() entirely, so lab sources that call gets()
 * no longer compile or link on modern Debian/Kali. This header restores the
 * original UNBOUNDED, VULNERABLE behaviour (read a line from stdin with no
 * length limit, keep going past the end of the buffer) via a macro rename,
 * so it works on every libc version and never clashes with a libc gets().
 *
 * It reads bytes until '\n' or EOF and does NOT stop on NUL bytes, matching
 * the real gets() over a socket. Authorised LOCAL practice use only.
 */
#ifndef VULN_COMPAT_H
#define VULN_COMPAT_H
#include <stdio.h>

static char *vuln_gets(char *s)
{
    int c;
    char *p = s;
    while ((c = getchar()) != EOF && c != '\n')
        *p++ = (char) c;        /* no bounds check - this is the bug */
    *p = '\0';
    if (c == EOF && p == s)
        return NULL;
    return s;
}

/* Every gets(buf) in the lab sources compiles to the shim above. */
#define gets vuln_gets

#endif /* VULN_COMPAT_H */
