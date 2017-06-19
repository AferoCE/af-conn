/*
 * Helper functions to perform basic hostname validation using OpenSSL.
 *
 * Please read "everything-you-wanted-to-know-about-openssl.pdf" before
 * attempting to use this code. This whitepaper describes how the code works,
 * how it should be used, and what its limitations are.
 *
 * Author:  Alban Diquet
 * License: See LICENSE (Curl license)
 *
 */

#include <strings.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "af_log.h"

// Borrow the curl hostname validation code and use it here.  I can't just link with it since it's not exported in the lib
#define CURL_HOST_NOMATCH 0
#define CURL_HOST_MATCH   1

/* Portable, consistent toupper (remember EBCDIC). Do not use toupper() because
 its behavior is altered by the current locale. */
static char Curl_raw_toupper(char in)
{
    switch (in) {
        case 'a':
            return 'A';
        case 'b':
            return 'B';
        case 'c':
            return 'C';
        case 'd':
            return 'D';
        case 'e':
            return 'E';
        case 'f':
            return 'F';
        case 'g':
            return 'G';
        case 'h':
            return 'H';
        case 'i':
            return 'I';
        case 'j':
            return 'J';
        case 'k':
            return 'K';
        case 'l':
            return 'L';
        case 'm':
            return 'M';
        case 'n':
            return 'N';
        case 'o':
            return 'O';
        case 'p':
            return 'P';
        case 'q':
            return 'Q';
        case 'r':
            return 'R';
        case 's':
            return 'S';
        case 't':
            return 'T';
        case 'u':
            return 'U';
        case 'v':
            return 'V';
        case 'w':
            return 'W';
        case 'x':
            return 'X';
        case 'y':
            return 'Y';
        case 'z':
            return 'Z';
    }
    return in;
}

/*
 * Curl_raw_equal() is for doing "raw" case insensitive strings. This is meant
 * to be locale independent and only compare strings we know are safe for
 * this.  See http://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for
 * some further explanation to why this function is necessary.
 *
 * The function is capable of comparing a-z case insensitively even for
 * non-ascii.
 */

static int Curl_raw_equal(const char *first, const char *second)
{
    while(*first && *second) {
        if (Curl_raw_toupper(*first) != Curl_raw_toupper(*second)) {
        /* get out of the loop as soon as they don't match */
            break;
        }

        first++;
        second++;
    }
    /* we do the comparison here (possibly again), just to make sure that if the
     loop above is skipped because one of the strings reached zero, we must not
     return this as a successful match */
    return (Curl_raw_toupper(*first) == Curl_raw_toupper(*second));
}

static int Curl_raw_nequal(const char *first, const char *second, size_t max)
{
    AFLOG_DEBUG3("Curl_raw_nequal::first=%s, second=%s, max=%d",
                 (first==NULL) ? "null" : first,
                 (second==NULL) ? "null": second,
                 max);

    while(*first && *second && max) {
        if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second)) {
            break;
        }
        max--;
        first++;
        second++;
    }
    if(0 == max)
        return 1; /* they are equal this far */

    return Curl_raw_toupper(*first) == Curl_raw_toupper(*second);
}

/*
 * Match a hostname against a wildcard pattern.
 * E.g.
 *  "foo.host.com" matches "*.host.com".
 *
 * We use the matching rule described in RFC6125, section 6.4.3.
 * http://tools.ietf.org/html/rfc6125#section-6.4.3
 *
 * In addition: ignore trailing dots in the host names and wildcards, so that
 * the names are used normalized. This is what the browsers do.
 *
 * Do not allow wildcard matching on IP numbers. There are apparently
 * certificates being used with an IP address in the CN field, thus making no
 * apparent distinction between a name and an IP. We need to detect the use of
 * an IP address and not wildcard match on such names.
 *
 * NOTE: hostmatch() gets called with copied buffers so that it can modify the
 * contents at will.
 *
 * Afero Note:
 * We modified the original hostmatch function to support hostname with more
 * than 3 labels.
 * For example: foo.us2aw.host.com
 */

int hostmatch(char *hostname, char *pattern)
{
    const char *pattern_label_end, *pattern_wildcard, *hostname_label_end;
    int wildcard_enabled;
    size_t prefixlen, suffixlen;
    unsigned char ignored[sizeof(struct in6_addr)];


    if ((hostname == NULL) || (pattern == NULL)) {
        return (CURL_HOST_NOMATCH);
    }


    AFLOG_DEBUG3("hostmatch:: Matching (hostname=%s vs pattern=%s", hostname, pattern);
    /* normalize pattern and hostname by stripping off trailing dots */
    size_t len = strlen(hostname);
    if(hostname[len-1]=='.')
        hostname[len-1]=0;
    len = strlen(pattern);
    if(pattern[len-1]=='.')
        pattern[len-1]=0;

    pattern_wildcard = strchr(pattern, '*');
    if(pattern_wildcard == NULL) {
        AFLOG_DEBUG3("hostmatch: failed, pattern_wildcard is NULL");
        return Curl_raw_equal(pattern, hostname) ?
        CURL_HOST_MATCH : CURL_HOST_NOMATCH;
    }
    AFLOG_DEBUG3("hostmatch: pattern=%s, pattern_wildcard=%s", pattern, pattern_wildcard);

    /* detect IP address as hostname and fail the match if so */
    if(inet_pton(AF_INET, hostname, ignored) > 0) {
        AFLOG_DEBUG3("hostmatch: failed, NO IPv4 address");
        return CURL_HOST_NOMATCH;
    } else if (inet_pton(AF_INET6, hostname, ignored) > 0) {
        AFLOG_DEBUG3("hostmatch: failed, NO IPv6 address");
        return CURL_HOST_NOMATCH;
    }

    /* We require at least 2 dots in pattern to avoid too wide wildcard
     match. */
    wildcard_enabled = 1;
    pattern_label_end = strchr(pattern, '.');
    if(pattern_label_end == NULL || strchr(pattern_label_end+1, '.') == NULL ||
       pattern_wildcard > pattern_label_end ||
       Curl_raw_nequal(pattern, "xn--", 4)) {
        wildcard_enabled = 0;
    }
    if(!wildcard_enabled) {
        AFLOG_DEBUG3("hostmatch:: NO wildcard. Exact match failed");
        return Curl_raw_equal(pattern, hostname) ?
        CURL_HOST_MATCH : CURL_HOST_NOMATCH;
    }

    // get the hostname label after the first dot
    // for example: conclave.prod.afero.io => host_name_label_end = .prod.afero.io
    hostname_label_end = strchr(hostname, '.');

    // comparing the pattern after the wildcard, but we should only compare
    // the part after the wildcard, not just after the first dot.  On the
    // other hand. We do want to confirm to the hostmatch format of x.y.z (or w.x.y.z)
    if (hostname_label_end != NULL) {
        int diff = strlen(hostname_label_end) - strlen(pattern_label_end);
        AFLOG_DEBUG3("hostmatch: diff=%d", diff);
        diff = (diff < 0) ? 0 : diff;
        hostname_label_end = hostname_label_end + diff;  // advance that much
        AFLOG_DEBUG3("hostmatch: Compare hostname_label_end=%s  pattern_end=%s",
                     hostname_label_end, pattern_label_end);

        if(hostname_label_end == NULL ||
           !Curl_raw_equal(pattern_label_end, hostname_label_end)) {
            AFLOG_DEBUG3("hostmatch: failed, pattern_end=%s, hostname_label_end=%s",
                         pattern_label_end, hostname_label_end);
            return CURL_HOST_NOMATCH;
         }
    }


    /* The wildcard must match at least one character, so the left-most
     label of the hostname is at least as large as the left-most label
     of the pattern. */
    if(hostname_label_end - hostname < pattern_label_end - pattern) {
        AFLOG_DEBUG3("hostmatch: failed, hostname_side=%d vs patten_side=%d",
                     (hostname_label_end - hostname), (pattern_label_end - pattern));
        return CURL_HOST_NOMATCH;
    }

    prefixlen = pattern_wildcard - pattern;
    suffixlen = pattern_label_end - (pattern_wildcard+1);
    int rc = Curl_raw_nequal(pattern, hostname, prefixlen) &&
    Curl_raw_nequal(pattern_wildcard+1, hostname_label_end - suffixlen,
                    suffixlen) ?
    CURL_HOST_MATCH : CURL_HOST_NOMATCH;

    return rc;
}
