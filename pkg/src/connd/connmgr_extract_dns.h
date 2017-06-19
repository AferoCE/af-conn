/*
* connmgr_extract_dns.h
*
* This contains the code implementation utilities or helper functions.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#ifndef _CONNMGR_EXTRACT_DNS_H_
#define _CONNMGR_EXTRACT_DNS_H_

#include <arpa/nameser.h>

/* The following dns packet definitions are based on:
 * target-mips_34kc_uClibc-0.9.33.2/tcpdump-full/tcpdump-4.5.1/nameser.h
 *
 * Disclaimer:  This is not a full DNS implementation, only the needed
 * type and enum are copied or defined.
 */

#if 0
/*
 * Internet nameserver port number
 * note: this is defined in include file <resolv.h>
 */
#ifndef NAMESERVER_PORT
    #define NAMESERVER_PORT     53
#endif

/*
 *  Port for multicast DNS; see
 *   http://files.multicastdns.org/draft-cheshire-dnsext-multicastdns.txt
 *
 *  for the current mDNS spec.
 **/

#define MULTICASTDNS_PORT   5353        //TODO - support this?

/*
 * Define constants based on rfc883
 */
#define PACKETSZ    512     /* maximum packet size */
#define MAXDNAME    256     /* maximum domain name */
#define MAXCDNAME   255     /* maximum compressed domain name */
#define MAXLABEL    63      /* maximum length of domain label */

/*
 * Type values for resources and queries
 * see target-mips_34kc_uClibc-0.9.33.2/tcpdump-full/tcpdump-4.5.1/nameser.h
 * for a complete list
 */
#define T_A         1       /* host address */
#define T_NS        2       /* authoritative server */
#define T_MD        3       /* mail destination */
#define T_MF        4       /* mail forwarder */
#define T_CNAME     5       /* connonical name */
#define T_SOA       6       /* start of authority zone */
#define T_MB        7       /* mailbox domain name */
#define T_MG        8       /* mail group member */
#define T_MR        9       /* mail rename name */
#define T_NULL      10      /* null resource record */
#define T_WKS       11      /* well known service */
#define T_PTR       12      /* domain name pointer */
#define T_HINFO     13      /* host information */
#define T_MINFO     14      /* mailbox information */
#define T_MX        15      /* mail routing information */
#define T_TXT       16      /* text strings */
#define T_AAAA      28      /* IP6 Address */

#endif  //


/*
 * Defines for handling compressed domain names, EDNS0 labels, etc.
 */
#ifndef INDIR_MASK
    #define INDIR_MASK  0xc0    /* 11.... */
#endif
#ifndef EDNS0_MASK
    #define EDNS0_MASK  0x40    /* 01.... */
#endif
#ifndef EDNS0_ELT_BITLABEL
    #define EDNS0_ELT_BITLABEL 0x01
#endif


/*
 * Structure for query header.
 */
typedef struct {
    u_int16_t id;       /* query identification number */
    u_int8_t  flags1;   /* first byte of flags */
    u_int8_t  flags2;   /* second byte of flags */
    u_int16_t qdcount;  /* number of question entries */
    u_int16_t ancount;  /* number of answer entries */
    u_int16_t nscount;  /* number of authority entries */
    u_int16_t arcount;  /* number of resource entries */
} CM_DNS_HEADER;

/*
 * Macros for subfields of flag fields.
 */
#define DNS_QR(np)  ((np)->flags1 & 0x80)       /* response flag */
#define DNS_OPCODE(np)  ((((np)->flags1) >> 3) & 0xF)   /* purpose of message */
#define DNS_AA(np)  ((np)->flags1 & 0x04)       /* authoritative answer */
#define DNS_TC(np)  ((np)->flags1 & 0x02)       /* truncated message */
#define DNS_RD(np)  ((np)->flags1 & 0x01)       /* recursion desired */

#define DNS_RA(np)  ((np)->flags2 & 0x80)       /* recursion available */
#define DNS_AD(np)  ((np)->flags2 & 0x20)       /* authentic data from named */
#define DNS_CD(np)  ((np)->flags2 & 0x10)       /* checking disabled by resolver */
#define DNS_RCODE(np)   ((np)->flags2 & 0xF)    /* response code */


//Constant sized fields of the resource record structure
//   name
//   type
//   class
//   ttl
//   rdlength
//   rdata
#pragma pack(push, 1)
struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int   ttl;
    unsigned short data_len;
};
#pragma pack(pop)


//Pointers to resource record contents
// data_len in the R_DATA tells how large this is.
struct RES_RECORD
{
    unsigned char   *name;
    struct R_DATA   *resource;
    unsigned char   *rdata;
};


// structure to store the afero whitelist related DNS info for connmgr
#define CM_WL_SERVICE_DN_LEN            (64 + 1)

/* We have a whitelist of all the services we support.
 *
 * For example, some of services we currently known are:
 *  conlave server - eg. conclave.afero.io
 *  echo server - eg. echo.afero.io
 *  log server - eg. squirrel.afero.io
 *  ota service
 */
#define CM_WL_MAX_NUM_ENTRIES           (10)

/* conclave may have multiple alias name depending on how the services
 * are deployed:
 *
 * For example:
 * Name :           conclave.dev.afero.io
 * has alias name : conclave-dev-2093121058.us-west-2.elb.amazonaws.com
 */
#define CM_SERVICE_MAX_DN_ALIASES       (2)

#define CM_DN_MAX_IPADDR                (12)


// record the IP address and its TTL value from the dns answer
typedef struct cm_dns_ip_ {
    uint8_t     inuse;
    uint32_t    ip_addr;
#define CM_DNS_IP_TTL_NONE         (0)
#define CM_DNS_IP_TTL_EXPIRED      (-1)
    uint32_t    ttl;            // ttl from the answer section
    time_t      updated_time;   // time when it was updated
#define CMD_DNS_ALLOW_EXPIRED_TIME (600)   // 10 mins
    time_t      expired_time;   // time when the rule was
} cm_dns_ip_rec_t;


/* This represent a whitelist, with its DNS info, including the IP */
typedef struct cm_wl_entry_ {
    // This is the service name, provided in the whitelist
    char        service_name[CM_WL_SERVICE_DN_LEN];

    // number of address this afero service mapped to.
    // from answer section
    uint8_t             num_iprec;
    cm_dns_ip_rec_t     ip_rec[CM_DN_MAX_IPADDR];
} cm_wl_entry_t;


typedef struct cm_dns_info_ {
    pthread_mutex_t     db_mutex;   // serialize access to the db
    uint8_t             num_wl_entries;
    cm_wl_entry_t       wl_entries[CM_WL_MAX_NUM_ENTRIES];
} cm_dns_info_t;


/* ----------------------------*/
/* whitelist dns db            */
/* ----------------------------*/

/* afero whitelist and its related dns info */
extern cm_dns_info_t    af_wl_dns_db;

/*
 * API to read the whitelist from the whitelist config file
 * it stores the service server name in wl_entries[].service_name
 *
 * [OUTPUT]:
 * dns_info  - the db contains the whitelist and dns mapping
 */
extern uint32_t
cm_read_whitelist(cm_dns_info_t   *dns_info);


/* routine to extract dns from the packet captured
 *
 * bp     - packet contains the dns data, starting at the DNS Header
 * length - the length of the packet
 * is_mdsn- is multicase dns supported? (1=yes, 0=NO), accept 0 now.
 */
extern void
cm_extract_dns_rrec(register const u_char *bp, u_int length, int is_mdns);


/* API to manage the dns ip addresses we extracted from the DNS answer
 *
 * wl_dn_entry_p:  db entry to this afero service on the whitelist
 * extracted_ip:   ip address, include info to manage it
 *
 * Note :
 * There is a design agreement or assumption here that HUBBY who is responsible
 * for connecting to the AFERO conclave service, makes a DNS query before connecting
 * to it.  Once the service is connected, HUBBY won't make another DNS query.  This
 * implies that the next DNS query may be due to HUBBY has been disconnected.
 * This assumption is used to manage the expiration and expunging of the IP
 * addresses in the record..
 */
extern
int cm_manage_dns_wl_ip_list(cm_wl_entry_t      *wl_dn_entry_p,
                             cm_dns_ip_rec_t     extracted_ip);


/* API to reset the DNS whitelist IP recored entires
 */
extern
void cm_dns_reset_wl_entries(void);


/* API to clean up the DNS whitelist DB
*/
extern
void cm_dns_wl_db_cleanup(void);


/* API to initialize the DNS whitelist DB */
extern
int cm_dns_init_wl_db(void);

#endif   // _CONNMGR_EXTRACT_DNS_H_
