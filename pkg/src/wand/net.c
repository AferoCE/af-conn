/*
 * net.c -- network watcher definitions
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Clif Liu and Tina Cheung
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "net.h"
#include "af_log.h"

static netwatch_callback_t sNetDownCallback;
static void *sNetDownContext;
static uint8_t sNetWatchThreadCreated = 0;
static pthread_t sNetWatchThread;
static char sErrBuf[PCAP_ERRBUF_SIZE];
static pcap_t *sPcapSession = NULL;
static struct bpf_program sPcapFilter;
static uint8_t sPcapFilterAllocated = 0;
static pthread_mutex_t sNetWatchThreadMutex = PTHREAD_MUTEX_INITIALIZER;
static int sNetWatchThreadExit = 0;
static int sNumConns;

#define PCAP_TIMEOUT       1000 // maximum time in ms pcap_next_ex executes
#define NET_CHECK_INTERVAL 5    // time between checks for expired packets
#define PACKET_EXPIRE_TIME 30   // time after which an unacked packet is considered expired

#define PKT_FLAGS_OCCUPIED (1 << 0)

typedef struct {
    struct timeval ts;
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t flags;
} conn_t;

struct __attribute__((__packed__)) my_ipv4 {
    uint8_t verHLen;
    uint8_t tos;
    uint16_t totalLen;
    uint16_t id;
    uint16_t fOffsetFlags;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t cksum;
    uint32_t srcAddr;
    uint32_t dstAddr;
};

struct __attribute__((__packed__)) my_tcp {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t offset;
    uint8_t flags;
};

#define TCP_FLAGS_FIN (1 << 0)
#define TCP_FLAGS_SYN (1 << 1)
#define TCP_FLAGS_ACK (1 << 4)

#define TCP_FLAGS_ONEBYTE (TCP_FLAGS_SYN | TCP_FLAGS_FIN)

#define MAX_OUTSTANDING_PACKETS 8
static conn_t sConns[MAX_OUTSTANDING_PACKETS];

static char *prv_ip_string(char *buffer, int len, uint32_t addr, uint16_t port)
{
    if (len < 22) {
        return NULL;
    }
    uint32_t addrNO = htonl(addr);
    sprintf(buffer, "%03d.%03d.%03d.%03d:%05d", addrNO >> 24, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff, port);
    return buffer;
}

/* return 0 if found, -1 if we can replace an existing packet, -2 if we'd have to add a new packet, -3 if we have no space to add new packets */
static int prv_find_packet(uint32_t srcAddr, uint32_t dstAddr, uint16_t srcPort, uint16_t dstPort, conn_t **pktP)
{
    int i = 0;
    int freeIndex = -1;
    int foundIndex = -1;
    while (i < sNumConns) {
        conn_t *p = sConns + i;
        if (p->flags & PKT_FLAGS_OCCUPIED) {
            if (p->srcAddr == srcAddr && p->dstAddr == dstAddr &&
                p->srcPort == srcPort && p->dstPort == dstPort) {
                foundIndex = i;
                break;
            }
        } else {
            if (freeIndex == -1) {
                freeIndex = i;
            }
        }
        i++;
    }
    if (foundIndex != -1) {
        *pktP = sConns + foundIndex;
        return 0;
    } else if (freeIndex != -1) {
        *pktP = sConns + freeIndex;
        sConns[freeIndex].flags = 0; /* initialize packet */
        return -1;
    } else {
        if (sNumConns < MAX_OUTSTANDING_PACKETS) {
            *pktP = sConns + sNumConns;
            sConns[sNumConns].flags = 0; /* initialize packet */
            return -2;
        } else {
            return -3;
        }
    }
}

static int prv_actual_num_conns(void)
{
    int i, n=0;
    for (i = 0; i < sNumConns; i++) {
        if (sConns[i].flags & PKT_FLAGS_OCCUPIED) {
            n++;
        }
    }
    return n;
}

//#define DEEP_DEBUG
#ifdef DEEP_DEBUG
static void print_packet(uint8_t *buf, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (i == 0)
            printf ("%02x", buf[i]);
        else
            printf (" %02x", buf[i]);
    }
    printf ("\n");
}
#endif

#define ETH_HEADER_LEN 14

static void prv_handle_packet(const struct pcap_pkthdr *h, const u_char *bytes)
{
#ifdef DEEP_DEBUG
    print_packet();
#endif
    struct my_ipv4 *ip = (struct my_ipv4 *)(bytes + ETH_HEADER_LEN);

    uint8_t version = ip->verHLen >> 4;
    if (version != 4) return;       /* only IPv4 supported */

    uint32_t length = h->len;       /* actual packet length */
    if (length < 40) return;        /* must have IP and TCP headers at the very least */

    uint8_t protocol = ip->protocol;
    if (protocol != 6) return;     /* must be a TCP header. UDP is ignored */

    uint32_t srcAddr = ip->srcAddr; /* keep everything in network byte order */
    uint32_t dstAddr = ip->dstAddr;

    uint16_t ipHeaderLen = (ip->verHLen & 0x0f) << 2;
    struct my_tcp *tcp = (struct my_tcp *)(bytes + ETH_HEADER_LEN + ipHeaderLen);

    uint16_t srcPort = tcp->srcPort;
    uint16_t dstPort = tcp->dstPort;
    uint32_t seqNum = ntohl(tcp->seqNum);
    uint32_t ackNum = ntohl(tcp->ackNum);

    uint16_t tcpHeaderLen = (tcp->offset & 0xf0) >> 2;
    uint16_t payloadLen;
    if (tcp->flags & TCP_FLAGS_ONEBYTE) {
        payloadLen = 1;
    } else {
        payloadLen = length - tcpHeaderLen - ipHeaderLen - ETH_HEADER_LEN;
    }

    if (g_debugLevel >= LOG_DEBUG4) {
        char bs[22];
        char bd[22];
        AFLOG_DEBUG4("packet:src=%s,dst=%s,len=%d,seq=%u,ack=%u",
            prv_ip_string(bs, sizeof(bs), srcAddr, srcPort),
            prv_ip_string(bd, sizeof(bd), dstAddr, dstPort),
            payloadLen, seqNum, ackNum);
    }
    conn_t *pkt;
    int status;
    if (payloadLen != 0) {
        status = prv_find_packet (srcAddr, dstAddr, srcPort, dstPort, &pkt);
        if (status == 0) {
            /* packet found */
            if (seqNum + payloadLen > pkt->seqNum) {
                pkt->seqNum = seqNum + payloadLen;
                pkt->ts = h->ts;
                AFLOG_DEBUG4("connection updated");
            }
        } else if (status == -1 || status == -2) {
            pkt->srcAddr = srcAddr;
            pkt->dstAddr = dstAddr;
            pkt->srcPort = srcPort;
            pkt->dstPort = dstPort;
            pkt->seqNum = seqNum + payloadLen;
            pkt->ts = h->ts;
            pkt->flags |= PKT_FLAGS_OCCUPIED;
            if (status == -2) {
                sNumConns++;
            }
            AFLOG_DEBUG4("connection created: nConns=%d", prv_actual_num_conns());
        } else if (status == -3) {
            /* ignore this packet */
            AFLOG_DEBUG4("netwatch:conn_overflow:max_conn=%d:too many connections", MAX_OUTSTANDING_PACKETS);
        }
    }

    if (tcp->flags & TCP_FLAGS_ACK) {
        status = prv_find_packet (dstAddr, srcAddr, dstPort, srcPort, &pkt);
        if (status == 0) {
            /* packet found */
            if (ackNum == pkt->seqNum) {
                pkt->flags &= ~PKT_FLAGS_OCCUPIED;
                AFLOG_DEBUG4("connection acked and removed:ackNum=%u,seqNum=%u,nConns=%d", ackNum, pkt->seqNum, prv_actual_num_conns());
            } else {
                AFLOG_DEBUG4("did not ack latest seqNum:ackNum=%u,seqNum=%u", ackNum, pkt->seqNum);
            }
        } else {
            AFLOG_DEBUG4("extra_ack=%u", ackNum);
        }
    }
}

extern int h_errno;

static int prv_check_dns(void)
{
    uint8_t buf[4096];
    int ret = 0;

    if (res_query("afero.io", ns_c_in, ns_t_ns, buf, sizeof(buf)) < 0) {
        AFLOG_ERR("netwatch:dns_fail:h_err=%s:dns lookup failed", hstrerror(h_errno));
        ret = -1;
    } else {
        AFLOG_DEBUG2("dns check succeeded");
    }
    return ret;
}

/* returns 0 if okay, -1 if network has gone down */
static int prv_handle_timeout(void)
{
    struct timespec now;
    int i, packetExpired = 0;

    clock_gettime(CLOCK_REALTIME, &now);

    /* check if any connections have been still for a long time */
    for (i = 0; i < sNumConns; i++) {
        conn_t *p = sConns + i;
        if (p->flags & PKT_FLAGS_OCCUPIED) {
            if (p->ts.tv_sec > now.tv_sec) {
                AFLOG_WARNING("netwatch:future_pkt:pkt_tv_sec=%d,now_tv_sec=%d:packet with timestamp in the future found",
                    (int)p->ts.tv_sec, (int)now.tv_sec);
            } else {
                int diff = now.tv_sec - p->ts.tv_sec;
                if (diff > PACKET_EXPIRE_TIME) {
                    packetExpired = 1;
                    /* recycle the packet */
                    p->flags &= ~PKT_FLAGS_OCCUPIED;
                }
            }
        }
    }

    if (packetExpired) {
        AFLOG_INFO("netwatch:expired::expired packet found");
        if (prv_check_dns() != 0) {
            return -1;
        } else {
            /* recycle all packets */
            for (i = 0; i < sNumConns; i++) {
                sConns[i].flags &= ~PKT_FLAGS_OCCUPIED;
            }
            sNumConns = 0;
        }
    } else {
        /* minimize packet count */
        int i, lastOccupied = -1;
        for (i = 0; i < sNumConns; i++) {
            if (sConns[i].flags & PKT_FLAGS_OCCUPIED) {
                lastOccupied = i;
            }
        }
        AFLOG_DEBUG4("minimized sNumConns:old=%d,new=%d", sNumConns, lastOccupied + 1);
        sNumConns = lastOccupied + 1;
    }

    return 0;
}

static char *my_pcap_geterr(void)
{
    if (sPcapSession == NULL) {
        return NULL;
    }
    strncpy(sErrBuf, pcap_geterr(sPcapSession), sizeof(sErrBuf));
    sErrBuf[sizeof(sErrBuf)-1] = '\0';
    return sErrBuf;
}

static void *prv_thread_entry(void *arg)
{
    struct timespec lastCheckTime;

    /* initialize dns lookup */
    if (res_init() < 0) {
        AFLOG_ERR("netwatch_init:res_init:errno=%d:res_init failed", errno);
    }
    sNumConns = 0;
    sNetWatchThreadExit = 0;

    clock_gettime(CLOCK_REALTIME, &lastCheckTime);

    while (1) {
        struct timespec now;
        struct pcap_pkthdr *h;
        const u_char *bytes;

        int status = pcap_next_ex(sPcapSession, &h, &bytes);
        if (status == 1) {
            /* got a packet */
            prv_handle_packet(h, bytes);
        } else if (status != 0) {
            AFLOG_ERR("netwatch:pcap_next_ex:error=\"%s\":", my_pcap_geterr());
            /* assume the network is down */
            (sNetDownCallback)(0, sNetDownContext);
            return NULL;
        }

        /* check if we should look for expired packets */
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec > lastCheckTime.tv_sec) {
            int diff = now.tv_sec - lastCheckTime.tv_sec;
            if (diff > NET_CHECK_INTERVAL) {
                lastCheckTime = now;
                if (prv_handle_timeout() < 0) {
                    /* call the network down callback */
                    (sNetDownCallback)(0, sNetDownContext);
                    return NULL;    /* immediately exit thread */
                }
            }
        }

        /* check if we need to commit suicide */
        pthread_mutex_lock(&sNetWatchThreadMutex);
        int exit_thread = sNetWatchThreadExit;
        pthread_mutex_unlock(&sNetWatchThreadMutex);
        if (exit_thread) {
            return NULL;
        }
    }
    return NULL;
}


int netwatch_init(char *dev, netwatch_callback_t callback, void *context)
{
    int err;

    if (dev == NULL || callback == NULL) {
        errno = EINVAL;
        return -1;
    }

    sNetDownCallback = callback;
    sNetDownContext = context;

    /* open pcap */
    sPcapSession = pcap_open_live(dev, BUFSIZ, 0, PCAP_TIMEOUT, sErrBuf);
    if (sPcapSession == NULL) {
        AFLOG_ERR("netwatch_init:pcap_open_live:err=\"%s\":can't open pcap", sErrBuf);
        netwatch_shutdown();
        return -1;
    }

    /* set up a filter to only look at tcp packets */
    if (pcap_compile(sPcapSession, &sPcapFilter, "tcp", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        AFLOG_ERR("netwatch_init:pcap_compile:error=\"%s\":can't compile filter", my_pcap_geterr());
    } else {
        sPcapFilterAllocated = 1;
        if (pcap_setfilter(sPcapSession, &sPcapFilter) < 0) {
            AFLOG_ERR("netwatch_init:pcap_setfilter:err=\"%s\":can't set filter", my_pcap_geterr());
        }
    }

    /* create the network watcher thread */
    err = pthread_create(&sNetWatchThread, NULL, prv_thread_entry, NULL);
    if (err < 0) {
        AFLOG_ERR("netwatch_init:create:err=%d:can't start netwatch thread", errno);
        errno = err;
        return -1;
    }
    sNetWatchThreadCreated = 1;

    return 0;
}


void netwatch_shutdown(void)
{
    void *res;

    if (sNetWatchThreadCreated) {
        /* tell thread to commit suicide */
        pthread_mutex_lock(&sNetWatchThreadMutex);
        sNetWatchThreadExit = 1;
        pthread_mutex_unlock(&sNetWatchThreadMutex);

        if (sPcapFilterAllocated) {
            pcap_freecode(&sPcapFilter);
            sPcapFilterAllocated = 0;
        }

        pthread_join(sNetWatchThread, &res);
        sNetWatchThreadCreated = 0;
    }

    if (sPcapSession) {
        pcap_close(sPcapSession);
        sPcapSession = 0;
    }
}

