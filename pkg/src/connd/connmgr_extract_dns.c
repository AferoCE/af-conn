/*
* connmgr_extract_dns.c
*
* This file contains the code that is part of extender FW management.
*
* The basic idea is that when there is ethernet or wifi connectivity,
* or no wan device (i.e no wwan0), then the bento can switch to become
* an extender and attempt to connect to a "master" bento.
*
* The same software runs on the "master" bento, as well as the "extender"
* bento.  Hence, it depends whether the bento is a master bento, or an
* extender master, you have a different set of FW rules.
*
* Where DNS resolved IP come into play?
* Every time hubby, the component responsible for connecting to the
* Afero serivce (such as conclave), makes a connection to conclave, it
* shall perform a DSN lookup on the conclave service (as it is hosted
* on the third party cloud service and behind a load balancer).
*
* The connmgr captured the DNS reply and extract the IP addresses.
* The IP addresses are used to punch FW holes for the extender's
* traffic.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#include <stdio.h>
#include <errno.h>
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
char *strcasestr(const char *haystack, const char *needle);
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <syslog.h>
#include <event.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>    // netlink - hotplug

//ref: build_dir/target-mips_34kc_uClibc-0.9.33.2/tcpdump-full/tcpdump-4.5.1/extract.h
#include "connmgr_extract_dns.h"

#include "connmgr.h"
#include "connmgr_util.h"
#include "traffic_mon.h"
#include "af_log.h"
#include "af_util.h"
#include "../include/hub_config.h"
#include "connmgr_hub_opmode.h"


// for wildcard match of the dns name
extern
int hostmatch(char *hostname, char *pattern);

/* afero whitelist and its related dns info */
cm_dns_info_t    af_wl_dns_db;


// File contains the whitelist of afero service
#define AFERO_WHITELIST_FILE    "/etc/config/afero_whitelist.txt"

//
// DNS extraction
//
static const char *ns_ops[] = {
        "",
        " inv_q",
        " stat",
        " op3",
        " notify",
        " update",
        " op6",
        " op7",
        " op8",
        " updataA",
        " updateD",
        " updateDA",
        " updateM",
        " updateMA",
        " zoneInit",
        " zoneRef",
};

static const char *ns_resp[] = {
        "",
        " FormErr",
        " ServFail",
        " NXDomain",
        " NotImp",
        " Refused",
        " YXDomain",
        " YXRRSet",
        " NXRRSet",
        " NotAuth",
        " NotZone",
        " Resp11",
        " Resp12",
        " Resp13",
        " Resp14",
        " NoChange",
};


/* Internal function
 */
static cm_wl_entry_t *
find_dns_sname_in_whitelist(unsigned char *name)
{
    int     i;
    int     result;
    uint8_t matched = 0;


    if (name == NULL) {
        return (NULL);
    }
    AFLOG_DEBUG1("find_dns_sname_in_whitelist:: name=%s", name);

    for (i=0; i<CM_WL_MAX_NUM_ENTRIES; i++) {
        if ((af_wl_dns_db.wl_entries[i].service_name == NULL) ||
            (af_wl_dns_db.wl_entries[i].service_name[0] == '\0')) {
            continue;
        }

        // do exact comparsion first, then do wildcard match
        result = strncmp((char *)name,
                         af_wl_dns_db.wl_entries[i].service_name,
                         strlen((char *)name));
        if (result == 0) {
            AFLOG_DEBUG2("find_dns_sname_in_whitelist:: i=%d, name =%s",
                         i,
                         af_wl_dns_db.wl_entries[i].service_name);
            return (&af_wl_dns_db.wl_entries[i]);
        }
        else {
            matched = hostmatch((char *)name, af_wl_dns_db.wl_entries[i].service_name);
            if (matched == 1) {
                AFLOG_DEBUG2("find_dns_sname_in_whitelist:: found i=%d, name =%s",
                             i,
                             af_wl_dns_db.wl_entries[i].service_name);
                return (&af_wl_dns_db.wl_entries[i]);
            }
        }
    }
    return (NULL);
}


/* ns_nskip
 *
 * internal routine to skip over a domain name
 * ref: see tcpdump implementation
 **/
static const u_char *
ns_nskip(register const u_char *cp,
         uint32_t cp_length,
         uint32_t *skip_len)
{
    register u_char i;


    if (cp == NULL) {
        return NULL;
    }

    *skip_len = 0;

    i = *cp++;
    *skip_len = i + 1;

    while (i) {
        if ((i & INDIR_MASK) == INDIR_MASK)
            return (cp + 1);

        if ((i & INDIR_MASK) == EDNS0_MASK) {
            int bitlen, bytelen;

            if ((i & ~INDIR_MASK) != EDNS0_ELT_BITLABEL)
                return(NULL); /* unknown ELT */

            if ((bitlen = *cp++) == 0)
                bitlen = 256;
            bytelen = (bitlen + 7) / 8;
            cp += bytelen;
        } else {
            cp += i;
        }

        i = *cp++;
        if (i != 0) {
            *skip_len = *skip_len + i + 1;
        }
        AFLOG_DEBUG3("ns_nskip:: i=%d, skip_len=%d", i, *skip_len);
    }
    return (cp);
}


/*
 * This extract the name of the resource record
 *
 * 4.1.3. Resource record format  (Ref: rfc1035)
 *
 * The answer, authority, and additional sections all share the same
 * format: a variable number of resource records, where the number of
 * records is specified in the corresponding count field in the header.
 * Each resource record has the following format:
 *                                   1  1  1  1  1  1
 *     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                                               |
 *   /                                               /
 *   /                      NAME                     /
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TYPE                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                     CLASS                     |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                      TTL                      |
 *   |                                               |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   |                   RDLENGTH                    |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *   /                     RDATA                     /
 *   /                                               /
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * Ref: rfc1035, see section 4.1.4. Message compression
 *
 * In order to reduce the size of messages, the domain system utilizes a
 * compression scheme which eliminates the repetition of domain names in a
 * message.  In this scheme, an entire domain name or a list of labels at
 * the end of a domain name is replaced with a pointer to a prior occurance
 * of the same name.
 *
 * The pointer takes the form of a two octet sequence:
 *
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *   | 1  1|                OFFSET                   |
 *   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * Note:
 * a) if the first two bits of the two octet is [ 1 | 1 ] => OFFSET
 *    the OFFSET tells you where to retrieve the next label of
 *    the name.
 * b) if the first two bits of the two octet is [ 0| 0 ] => ptr
 *    to raw data
 *
 * To calculate the OFFSET
 * 1.  read the first octet (Value_1) * (2 to the power of 8)
 *     (2^8 = 256)
 *
 * 2. read the 2nd octet (Value_2)
 * 3  We have to take the value of the first 2 bits being [ 1 | 1 ]
 *    11000000 00000000 = 49152
 *
 * 4. The value of the OFFSET = Value_1 * 256 + Value_2 - 49152
 *
 **/
static u_char *
cm_read_dns_rec_name(unsigned char *reader,   // ptr to current position
                     unsigned char *buffer,   // ptr to the original buf, minus header
                     int           *count,
                     unsigned char *name_buf, // holder for the name
                     int           name_len)  // length of the name buffer
{
    unsigned char *name = name_buf;
    unsigned int p=0, jumped=0, offset;
    int i, j;
    int len = 0;


    if ((reader == NULL) || (buffer == NULL) || (name_buf == NULL)) {
        AFLOG_ERR("cm_read_dns_rec_name:: Invalid input:reader=%p, buffer=%p, name_buf=%p, name_len=%d",
                  reader, buffer, name_buf, name_len);
        return NULL;
    }

    *count = 1;
    name[0]='\0';

    //read the names in format: 3www6google3com
    while(*reader!=0)
    {
        // if domain name can be compressed, in the octet, the first two bits
        // tell us if it is a label and needs to jump to a location provided by the offset
        // 11000000 = 192
        if(*reader>=192) {  // the first two bits are 11 => need to jump to offset
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else {
            if (len < name_len) {
                name[p++] = *reader;
                len++;
            }
            else {
                AFLOG_WARNING("cm_read_dns_rec_name:: name is trauncated");
            }
        }

        reader = reader+1;

        if(jumped == 0) {
            *count = *count + 1; //if we haven't jumped to another location then we can count up
        }
    }

    name[p] = '\0'; //string complete
    len++;
    if(jumped == 1) {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //example: convert 3www6google3com0 to www.google.com
    for(i=0; i<(int)strlen((const char*)name); i++) {
        p=name[i];
        for(j=0; j<(int)p; j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}


/* cm_dns_extract_dns_rrec
 *  - API to extract the DNS answer when a DNS reply packet is captured.
 *
 * Implemenation notes:
 *
 * All DNS packets have a structure that is
 * +---------------------+
 * | Header              |
 * +---------------------+
 * | Question            |
 * +---------------------+
 * | Answer              |
 * +---------------------+
 * | Authority           |
 * +---------------------+
 * | Additional          |
 * +---------------------+
 *
 * The header describes the type of packet and which fields are contained in the packet. Following
 * the header are a number of questions, answers, authority and additionals records.
 *
 * Note:
 * As it turns out, we only really care about the answer section (for it
 * contains the IP addresses.
 *
 * is_mdns:  should be zero (as multicast dns is not supported).
 */
void
cm_extract_dns_rrec(register const u_char *bp, u_int length, int is_mdns)
{
    register const      CM_DNS_HEADER *np;
    register int        qdcount, ancount, nscount, arcount;
    uint16_t            i, j;
    uint32_t            rest_pkt_len;
    struct RES_RECORD   answers[20];
    struct sockaddr_in  addr;
    unsigned char       temp_name[256];
    uint16_t            type;
    u_char              *data = NULL;
    uint16_t            data_len;
    cm_wl_entry_t       *wl_dn_entry_p = NULL;


    /* if FW functionality is disable - then do nothing */
    if (CM_IS_FIREWALL_DISABLED) {
        return;
    }

    memset(answers, 0, sizeof(answers));
    rest_pkt_len = length;

    np = (const CM_DNS_HEADER *) bp;
    /* get the byte-order right */
    qdcount = ntohs(np->qdcount);
    ancount = ntohs(np->ancount);
    nscount = ntohs(np->nscount);
    arcount = ntohs(np->arcount);

    AFLOG_DEBUG2("dns_extract_dns_rrec::len=%d, qdcount=%d, ancount=%d, nscount=%d, arcount=%d",
                 length, qdcount, ancount, nscount, arcount);

    if (DNS_QR(np)) {
        /* this is a response */
        AFLOG_DEBUG2("dns_extract_dns_rrec:: DNS reply, id=%d, %s%s%s%s%s%s",
               ntohs(np->id), // EXTRACT_16BITS(&np->id),
               ns_ops[DNS_OPCODE(np)],
               ns_resp[DNS_RCODE(np)],
               DNS_AA(np) ? "*" : "",
               DNS_RA(np) ? "" : "-",
               DNS_TC(np) ? "|" : "",
               DNS_AD(np) ? "$" : "");
    }

    data = (u_char *)bp + 12;  // dns header size is 12
    rest_pkt_len = rest_pkt_len - 12;

    // Question section - we don't need data from this section
    if (qdcount) {  // skip question section
        while (qdcount--) {
            uint32_t  skip_len;
            // skip the query name
            if ((data = (u_char *)ns_nskip(data, rest_pkt_len, &skip_len)) == NULL)
                goto dns_end;
            rest_pkt_len = rest_pkt_len - skip_len;
            data = data + 4;  // skip qtype & qclass
            rest_pkt_len = rest_pkt_len - 4;
        }
    }

    //Start reading answers
    int stop = 0;
    for(i=0; i<ancount; i++) {
        memset(temp_name, 0, sizeof(temp_name));
        answers[i].name = cm_read_dns_rec_name(data, (u_char *) bp, &stop,
                                               temp_name,
                                               sizeof(temp_name));
        data = data + stop;
        answers[i].resource = (struct R_DATA *) (data);

        if (answers[i].resource == NULL) {
            AFLOG_ERR("dns_extract_dns_rrec:: ANSWER: No resource in record");
            continue;   // bad data, skip this one
        }
        AFLOG_DEBUG2("dns_extract_dns_rrec:: ANSWER: i=%d, name=%s type=%d, _class=%d, ttl=%d, data_len=%d",
                     i, answers[i].name,
                     ntohs(answers[i].resource->type),
                     ntohs(answers[i].resource->_class),
                     ntohl(answers[i].resource->ttl),
                     ntohs(answers[i].resource->data_len));
        data = data + sizeof(struct R_DATA);

        /* process this record */
        // Is this DNS request one of our whitelist services?
        type = ntohs(answers[i].resource->type);
        data_len = ntohs(answers[i].resource->data_len);
        if (type == T_CNAME) { // connonical name
            wl_dn_entry_p = find_dns_sname_in_whitelist(temp_name);
            AFLOG_DEBUG2("dns_extract_dns_rrec:: wl_dn_entry_p=%p", wl_dn_entry_p);

            if (wl_dn_entry_p == NULL) { // not AFERO service, don't care
                goto dns_end;
            }
            data = data + data_len;
        }
        else if (type == T_A) {// its an ipv4 address
            uint32_t        data_len = ntohs(answers[i].resource->data_len);
            uint32_t        ipaddr;
            cm_dns_ip_rec_t iprec;
            ipaddr = *(uint32_t *)data;
            addr.sin_addr.s_addr = ipaddr; //working without ntohl
            AFLOG_DEBUG1("dns_extract_dns_rrec:: ANSWER: has IPv4 address : %d (%s), name=%s",
                           ipaddr, inet_ntoa(addr.sin_addr), answers[i].name);

            memset(&iprec, 0, sizeof(cm_dns_ip_rec_t));
            iprec.ttl     = ntohl(answers[i].resource->ttl);
            iprec.inuse   = 1;
            iprec.ip_addr = ipaddr;
            iprec.updated_time = time(NULL);
            iprec.expired_time = 0;

            // find the entry in the whitelist
            if (wl_dn_entry_p == NULL) {
                wl_dn_entry_p = find_dns_sname_in_whitelist(answers[i].name);
            }

            /* Note: the dns wl entries are reset whenever an interface is up.
             * The reason for this: the firewall rules are reloaded every time an
             * interface is up, and we need to clear the dns ip mapping entries
             * so we could re-populate the FW rules with these dns IP entries.
             */
            cm_manage_dns_wl_ip_list(wl_dn_entry_p, iprec);
            data = data + data_len;
        }
        else if (type == T_AAAA) {
            AFLOG_DEBUG1("cm_extract_dns_rrec:: ANSWER: IPv6 address");
            // just copy the data over for now
            //af_log_buffer(1, "IPV6::", data, ntohs(answers[i].resource->data_len));
            answers[i].rdata = (unsigned char *) malloc(ntohs(answers[i].resource->data_len));
            for (j = 0; j < ntohs(answers[i].resource->data_len); j++) {
                answers[i].rdata[j] = data[j];
            }
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
            data = data + data_len;
        } else if (type == T_PTR) {
                unsigned  char rdata[512];

                memset(rdata, 0, sizeof(rdata));
                //af_log_buffer(1, "T_PTR::", data, ntohs(answers[i].resource->data_len));

                cm_read_dns_rec_name(data, (u_char *) bp, &stop, rdata, sizeof(rdata));
                AFLOG_DEBUG2("cm_extract_dns_rrec:: ANSWER: PTR - rdata=%s", rdata);
                data = data + stop;
        }
        else {  // process so we know what to skip
            unsigned char rdata[512];
            cm_read_dns_rec_name(data, (u_char *) bp, &stop, rdata, sizeof(rdata));
            AFLOG_DEBUG2("cm_extract_dns_rrec:: ANSWER: type=%d - %s", type, rdata);
            data = data + stop;
        }
    }

    AFLOG_DEBUG2("cm_extract_dns_rrec::  DONE WITH ANSWER");

dns_end:
    return;
}



/*----------------------------------------------------*/
/*    whitelist                                       */
/*----------------------------------------------------*/

/* is_blank_line
 *
 * Return:
 *   True (1) - if the line is empty
 *   False (0) - if the line is not empty
 */
static int
is_blank_line(const char *line) {
    const char accept[]=" \t\r\n"; /* white space characters (fgets stores \n) */
    return (strspn(line, accept) == strlen(line));
}

/* cm_read_whitelist
 *
 * Read the afero whitelist from the file (AFERO_WHITELIST_FILE)
 * and store the service domain name
 */
uint32_t
cm_read_whitelist(cm_dns_info_t   *dns_info)
{
    FILE        *fp = NULL;
    char        line[128];
    uint32_t    len;
    uint32_t    count = 0;


    /* open the file to read only */
    fp = fopen(AFERO_WHITELIST_FILE, "r");
    if (fp == NULL) {
        AFLOG_ERR("cm_read_whitelist:File(%s) doesn't exist; using empty whitelist", AFERO_WHITELIST_FILE);
        return 0;
    }

    memset(line, 0, sizeof(line));
    while ( fgets(line, sizeof(line), fp) != NULL ) { /* read a line */
        // skip empty line and comment starting with #
        if (is_blank_line(line)) {
            continue;
        }
        else if (line[0] == '#') {
            continue;
        }

        line[strcspn(line, "\r\n")] = 0;  //remove return and/or endline
        len = strlen(line);
        if (len < CM_WL_SERVICE_DN_LEN) {
            if (count < CM_WL_MAX_NUM_ENTRIES) {
                strncpy(dns_info->wl_entries[count].service_name, line, len);
                dns_info->wl_entries[count].service_name[len] = '\0';
                AFLOG_DEBUG1("cm_read_whitelist:: count=%d, service_name=%s",
                             count, dns_info->wl_entries[count].service_name);
                count++;
            }
            else {
                AFLOG_ERR("cm_read_whitelist:: Number of service whitelist (%d) exceeds maximum (%d)",
                          count, CM_WL_MAX_NUM_ENTRIES);
            }
        }
        else {
            AFLOG_ERR("cm_read_whitelist:: Service DN length (%d) exceeds maximum length(%d)",
                    len, CM_WL_SERVICE_DN_LEN);
        }
        memset(line, 0, sizeof(line));
    }
    dns_info->num_wl_entries = count;

    fclose ( fp );
    return 0;
}


static  cm_dns_ip_rec_t *
cm_dns_find_ip_rec (cm_wl_entry_t    *wl_entry_p,
                    uint32_t         ipaddr)
{
    int                 i;

    if (wl_entry_p) {
        for (i = 0; i < CM_DN_MAX_IPADDR; i++) {
            if (wl_entry_p->ip_rec[i].ip_addr == ipaddr) {
                return (&wl_entry_p->ip_rec[i]);
            }
        }
    }

    return NULL;
}

static  cm_dns_ip_rec_t *
cm_dns_find_free_iprec_entry(cm_wl_entry_t    *wl_entry_p)
{
    int i;

    if (wl_entry_p) {
        for (i = 0; i < CM_DN_MAX_IPADDR; i++) {
            if (wl_entry_p->ip_rec[i].inuse == 0) {
                return (&wl_entry_p->ip_rec[i]);
            }
        }
    }

    return NULL;
}

/*
 * route to log a particular entry
 */
static void
cm_dns_log_wl_entry(cm_wl_entry_t  *wl_entry_p)
{
    int                 count = 0;
    int                 i = 0;
    struct sockaddr_in  addr;
    char                upt_buf[60];
    char                expired_buf[60];


    if (wl_entry_p != NULL) {
        AFLOG_INFO("cm_wl_entry:: service name: %s", wl_entry_p->service_name);
        AFLOG_INFO("cm_wl_entry:: has (%d) of IP records:", wl_entry_p->num_iprec);

        while ((count < wl_entry_p->num_iprec) && (i < CM_DN_MAX_IPADDR)) {
            if ( wl_entry_p->ip_rec[count].inuse == 1) {
                memset(&addr, 0, sizeof(addr));
                memset(upt_buf, 0, sizeof(upt_buf));
                memset(expired_buf, 0, sizeof(expired_buf));

                ctime_r(&wl_entry_p->ip_rec[count].updated_time, upt_buf);
                ctime_r(&wl_entry_p->ip_rec[count].expired_time, expired_buf);

                addr.sin_addr.s_addr = wl_entry_p->ip_rec[count].ip_addr;
                AFLOG_INFO("cm_wl_entry::   ip=%s, updated_time=%d(%s), ttl=%d %s %s",
                           inet_ntoa(addr.sin_addr),
                           (int) (wl_entry_p->ip_rec[count].updated_time),
                           upt_buf,
                           wl_entry_p->ip_rec[count].ttl,
                           ((wl_entry_p->ip_rec[count].ttl == CM_DNS_IP_TTL_EXPIRED) ? ", EXPIRED at" : ""),
                           ( (wl_entry_p->ip_rec[count].expired_time == 0) ? "" : expired_buf)
                         );
                count ++;
            }

        i++;
        }
    }
    return;
}

/*
 * Mark the IP address(es) for a particular service to be expired
 *
 * update_time is the time this IP address was recorded from the dns answer.
 * we use the current time (cur_time), if the difference between the cur_time
 * and the update_time is less than zero (diff = cur_time - update_time), then
 * we mark this IP address as expired.
 *
 */
static void
cm_dns_expire_wl_ip(cm_wl_entry_t  *wl_dn_entry_p)
{
    uint32_t    i;
    time_t      cur_time = time(NULL);
    time_t      time_passed = 0;
    struct sockaddr_in  addr;

    if (wl_dn_entry_p == NULL) {
        AFLOG_INFO("cm_dns_expire_wl_ip:: Invalid DN whitelist entry");
        return;
    }

    AFLOG_DEBUG1("cm_dns_expire_wl_ip:: service=%s, check for expired entry",
                 wl_dn_entry_p->service_name);
    for (i=0; i<CM_DN_MAX_IPADDR; i++) {
        // the IP entry is inuse, and not expired, then we check to see
        // if it has expired.

        AFLOG_DEBUG2("cm_dns_expire_wl_ip:: -- i=%d, inuse=%d, ttl=%d",
                     i,
                     wl_dn_entry_p->ip_rec[i].inuse,
                     wl_dn_entry_p->ip_rec[i].ttl);

        if ((wl_dn_entry_p->ip_rec[i].inuse == 1) &&
            (wl_dn_entry_p->ip_rec[i].ttl != CM_DNS_IP_TTL_EXPIRED)) {

            // calculate the time between now from when it was updated
            time_passed = cur_time - wl_dn_entry_p->ip_rec[i].updated_time;

            // based on the TTL (which is the DNS server's cache time, this
            // entry should be expired.  We mark it so.
            if ((time_passed - wl_dn_entry_p->ip_rec[i].ttl) < 0) {
                addr.sin_addr.s_addr = wl_dn_entry_p->ip_rec[i].ip_addr;

                wl_dn_entry_p->ip_rec[i].ttl = CM_DNS_IP_TTL_EXPIRED;
                wl_dn_entry_p->ip_rec[i].expired_time = time(NULL);

                AFLOG_INFO("cm_dns_expire_wl_ip:: service=%s, ip=(%d - %s), EXPIRED",
                           wl_dn_entry_p->service_name,
                           wl_dn_entry_p->ip_rec[i].ip_addr,
                           inet_ntoa(addr.sin_addr));
            }
        }
    }
        // this is not the most efficient way, but it is sufficient
        // now let's expunge the expired IP address (i.e delete the
        // FW rules and remove the list from this list
        // Rule to expunge:
        // 1.  Uses the expired_time, calculate the time passed between
        //     now and the marked expired_time.  if it is greater than
        //     3600sec or an hour, then this means this is no longer in use
        //     and we can remove it.
    for (i=0; i<CM_DN_MAX_IPADDR; i++) {
        if ((wl_dn_entry_p->ip_rec[i].inuse == 1) &&
            (wl_dn_entry_p->ip_rec[i].ttl == CM_DNS_IP_TTL_EXPIRED)) {

            time_passed = cur_time - wl_dn_entry_p->ip_rec[i].expired_time;

            if (time_passed > CMD_DNS_ALLOW_EXPIRED_TIME) {
                addr.sin_addr.s_addr = wl_dn_entry_p->ip_rec[i].ip_addr;

                // remove the forwarding FW rule here
                AFLOG_INFO("cm_dns_expire_wl_ip:: service=%s, ip=(%d - %s), EXPUNGED",
                           wl_dn_entry_p->service_name,
                           wl_dn_entry_p->ip_rec[i].ip_addr,
                           inet_ntoa(addr.sin_addr));

                af_util_system("/usr/bin/fwcfg del %s %s",
                               inet_ntoa(addr.sin_addr),
                               wl_dn_entry_p->service_name);

                if (cm_wifi_opmode == HUB_WIFI_OPMODE_MASTER) {
                    af_util_system("/usr/bin/fwcfg del_forwarding %s %s",
                    inet_ntoa(addr.sin_addr), wl_dn_entry_p->service_name);
                }
                wl_dn_entry_p->ip_rec[i].ttl = CM_DNS_IP_TTL_NONE;
                wl_dn_entry_p->ip_rec[i].expired_time = 0;
                wl_dn_entry_p->ip_rec[i].updated_time = 0;
                wl_dn_entry_p->ip_rec[i].inuse = 0;
                wl_dn_entry_p->ip_rec[i].ip_addr = 0;

                // decrement the number IP records
                wl_dn_entry_p->num_iprec++;
            }
        }  // expired
    }

    return;
}


/* cm_manage_wl_ip_list
 *
 * [in parameters]
 * wl_dn_entry_p:   db entry points to the AFERO service that the DNS
 *                  'answer' is for.
 * extracted_ipaddr: the IPv4 address extracted from the DNS reply
 *                  for the specified AFERO service.
 *
 *
 */
int cm_manage_dns_wl_ip_list(cm_wl_entry_t      *wl_dn_entry_p,
                             cm_dns_ip_rec_t    extracted_ip)
{
    cm_dns_ip_rec_t     *iprec_p = NULL;
    struct sockaddr_in  addr;
    int                 rc = -1;
    char                buf[60];


    /* if FW functionality is disable - then do nothing */
    if (CM_IS_FIREWALL_DISABLED) {
        return (0);
    }

    if (wl_dn_entry_p == NULL) {
        AFLOG_ERR("cm_manage_wl_ip_list:: Invalid whitelist db entry pointer");
        return (rc);
    }


    // *****************************
    // MUTEX
    // *****************************
    pthread_mutex_lock(&af_wl_dns_db.db_mutex);


    // search through the current list to see if the ip address is already
    // in it.
    // If it is
    //      update the entry.
    // else
    //      add to the entry
    iprec_p = cm_dns_find_ip_rec(wl_dn_entry_p,  extracted_ip.ip_addr);
    if (iprec_p != NULL) {
        iprec_p->inuse   = 1;
        iprec_p->ip_addr = extracted_ip.ip_addr;
        iprec_p->ttl     = extracted_ip.ttl;
        iprec_p->updated_time = extracted_ip.updated_time;   // the time we got this ip
        iprec_p->expired_time = 0;

        memset(buf, 0, sizeof(buf));
        ctime_r(&iprec_p->updated_time, buf);
        addr.sin_addr.s_addr = iprec_p->ip_addr;
        AFLOG_DEBUG1("cm_manage_dns_wl_ip_list::** UPDATED IP **, addr=%s, ttl=%d, %d(%s)",
                     inet_ntoa(addr.sin_addr), iprec_p->ttl,
                     (int) iprec_p->updated_time, buf);

        // ONLY add if the rule is not already in it.
        af_util_system("/usr/bin/fwcfg add %s \"%s\" 1",
                        inet_ntoa(addr.sin_addr),
                        wl_dn_entry_p->service_name);

        // if this is AP (ie. master BENTO)
        if (cm_wifi_opmode == HUB_WIFI_OPMODE_MASTER) {
            af_util_system("/usr/bin/fwcfg add_forwarding %s \"%s\" 1",
            inet_ntoa(addr.sin_addr), wl_dn_entry_p->service_name);
        }

        rc = 0;
    }
    else {
        iprec_p = cm_dns_find_free_iprec_entry(wl_dn_entry_p);
        if (iprec_p != NULL) {
            *iprec_p = extracted_ip;

            addr.sin_addr.s_addr = iprec_p->ip_addr;
            memset(buf, 0, sizeof(buf));
            ctime_r(&iprec_p->updated_time, buf);

            AFLOG_DEBUG1("cm_manage_dns_wl_ip_list::ADDED IP and FW, addr=%s, ttl=%d, %d(%s)",
                         inet_ntoa(addr.sin_addr), iprec_p->ttl,
                         (int) iprec_p->updated_time, buf);

            // increment the number of entries
            wl_dn_entry_p->num_iprec++;
            rc = 0;

            af_util_system("/usr/bin/fwcfg add %s %s",
                            inet_ntoa(addr.sin_addr),
                            wl_dn_entry_p->service_name);

            // if this is AP (ie. master BENTO)
            if (cm_wifi_opmode == HUB_WIFI_OPMODE_MASTER) {
                af_util_system("/usr/bin/fwcfg add_forwarding %s %s",
                inet_ntoa(addr.sin_addr), wl_dn_entry_p->service_name);
            }
        }
        else {
            AFLOG_ERR("cm_manage_dns_wl_ip_list: ALERT, failed to find free slot for IP rec");
        }
    }

    /* we want to expire IP address from previous instance of DNS query */
    cm_dns_expire_wl_ip(wl_dn_entry_p);


    // *****************************
    // END MUTEX
    // *****************************
    pthread_mutex_unlock(&af_wl_dns_db.db_mutex);


    // let's log the ip mapping info (good for debugging).
    cm_dns_log_wl_entry(wl_dn_entry_p);

    return (rc);
}


/* cm_dns_force_expire_wl
 *
 * API to reset the DNS whitelist IP address mapping entries.  This
 * is currently done whenver an interface is determined to be up.
 *
 * The FW table is reloaded, and re-populated everytime an interface
 * is up. The dns whitelist IP address mapping list is used to punch holes
 * for the services the platform provides.  Hence, we need to reset
 * the entries so these IP addresses can be added to the whitelist rules.
 * (Note: we only add IP address to the FW rules the first time it is
 *        seen, so we don't fill up the iptables.
 */
void
cm_dns_reset_wl_entries(void)
{
    int   i;

    /* if FW functionality is disable - then do nothing */
    if (CM_IS_FIREWALL_DISABLED) {
        return;
    }

    // ************
    // MUTEX
    // ************
    pthread_mutex_lock(&af_wl_dns_db.db_mutex);

    for (i=0; i<af_wl_dns_db.num_wl_entries; i++) {
        if (af_wl_dns_db.wl_entries[i].num_iprec > 0) {
            AFLOG_DEBUG1("cm_dns_reset_wl_entries:: service=%s, RESET its DNS IP mapping entries",
                         af_wl_dns_db.wl_entries[i].service_name);

            memset(af_wl_dns_db.wl_entries[i].ip_rec, 0, sizeof(af_wl_dns_db.wl_entries[i].ip_rec));
            af_wl_dns_db.wl_entries[i].num_iprec = 0;
        }
    }

    // ************
    // END MUTEX
    // ************
    pthread_mutex_unlock (&af_wl_dns_db.db_mutex);

    return;
}


/* cm_dns_init_wl_db()
 *
 * API to initialize the DNS service whitelist DB.
 *  - initialize the mutex used to serialize the DB access.
 */
int
cm_dns_init_wl_db(void)
{
	/* if FW functionality is disable - then do nothing */
    if (CM_IS_FIREWALL_DISABLED) {
        return (0);
    }

    memset(&af_wl_dns_db, 0, sizeof(af_wl_dns_db));

    if (pthread_mutex_init(&af_wl_dns_db.db_mutex, NULL) != 0) {
        AFLOG_ERR("cm_dns_init_wl_db:: failed to init pthread_mutex_t");
        return (-1);
    }

    if (cm_read_whitelist(&af_wl_dns_db)) {
        AFLOG_ERR("cm_dns_init_wl_db:: failed to read the whitelist");

        pthread_mutex_destroy(&af_wl_dns_db.db_mutex);
        return (-1);
    }

    return 0;
}


/* cm_dns_wl_db_cleanup
 *
 * House cleaning related to the DNS whitelist IP address mapping DB.
 * - destroy the mutex
 */
void
cm_dns_wl_db_cleanup(void)
{
    /* if FW functionality is disable - then do nothing */
    if (CM_IS_FIREWALL_DISABLED) {
        return;
    }

    pthread_mutex_destroy(&af_wl_dns_db.db_mutex);

    return;
}
