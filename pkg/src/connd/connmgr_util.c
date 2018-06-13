/*
* connmgr_util.c
*
* This contains the code implementation utilities or helper functions.
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
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>    // netlink - hotplug

#include "connmgr.h"
#include "connmgr_util.h"
#include "traffic_mon.h"
#include "af_log.h"
#include "../include/hub_config.h"


/*
 * perform system call to ping an known ipaddress.
 * ping -w 1 -c1 <address>
 *  (-w)ait for 1 sec
 *  (-c)ount for 1
 *  (-I)nterface wlan0
 */
#define   PING_GOOGLE_STR    "ping -w 1 -c 1 -I wlan0 8.8.8.8 | grep seq="
#define   CONNMGR_PING_STR   PING_GOOGLE_STR


/* get the IP (V4) address of the specified itf_name
 *
 * support IPv4 only for now
 **/
int get_itf_ipaddr(const char   *itf_name,
                    int          domain,  // AF_INET, AF_INET6
                    char         *ipaddr,
                    size_t       addr_len)
{
    int             fd;
    struct ifreq    ifr;
    int             rc = -1;


    fd = socket(domain, SOCK_DGRAM, 0);
    if (fd < 0) {
        return (rc);
    }

    ifr.ifr_addr.sa_family = domain;                /* IPv4 IP address or IPv6*/
    strncpy(ifr.ifr_name, itf_name, IFNAMSIZ-1);    /* attach the itf_name */
    rc = ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    if ((rc == 0) && (ipaddr != NULL) && (addr_len > 1)) {
        strncpy(ipaddr, inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr), addr_len - 1);
    }
    return (rc);
}


/*
 * in_cksum --
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 * -- from the "open source"
 */
unsigned
short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;


    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);       /* add hi 16 to low 16 */
    sum += (sum >> 16);                       /* add carry */
    answer = ~sum;                            /* truncate to 16 bits */
    return (answer);
}


cm_conn_monitor_cb_t *
cm_find_monitored_net_obj(const char *ifname)
{
    int i, len;

    if (ifname == NULL) {
        return NULL;
    }
    len = strlen(ifname);
    for (i=0; i<CONNMGR_NUM_MONITORED_ITF; i++) {
        if (strncmp(cm_monitored_net[i].dev_name, ifname, len) == 0) {
            return (&cm_monitored_net[i]);
        }
    }
    return NULL;
}

/* open an hotplug event netlink socket to listen for net device events */
int
cm_open_netlink_socket (int sock_type, int prot_family, int32_t nl_group)
{
    struct sockaddr_nl     nls;
    int                    nl_fd = -1;


    /* pen hotplug event netlink socket */
    memset(&nls, 0, sizeof(struct sockaddr_nl));
    nls.nl_family = AF_NETLINK;
    nls.nl_pid = getpid();
    //nls.nl_groups = -1;
    nls.nl_groups = nl_group;

    //nl_fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
    nl_fd = socket(PF_NETLINK, sock_type, prot_family);
    if (bind(nl_fd, (void *)&nls, sizeof(struct sockaddr_nl))) {
        AFLOG_ERR("cm_open_netlink_socket:: bind failed, nf_fd=%d",nl_fd);
        close (nl_fd);
        return (-1);
    }

    return nl_fd;
}


static const char *CM_UEVENT_ADD    = "add";
static const char *CM_UEVENT_REMOVE = "remove";
static const char *CM_UEVENT_CHANGE = "change";

void
cm_util_parse_uevent(char *recv_buffer, int  len, cm_parse_uevent_t *parse_uevent)
{
    char *name   = NULL;
    int   i;


    if ((len < 0) || (recv_buffer == NULL)) {
        return;
    }
    if (parse_uevent == NULL) {
        return;
    }

    AFLOG_DEBUG3("cm_util_parse_uevents::len=%d, uevent msg=%s", len, recv_buffer);

    memset(parse_uevent, 0, sizeof(cm_parse_uevent_t));
    // find the name
    name = strrchr(recv_buffer, '/');
    if (name == NULL) {
        return;
    }
    name = name + 1;
    AFLOG_DEBUG2("cm_util_parse_uevents:: dev name=%s", name);

    //we are only interested in the network devices: eth0, wlan0, wwan0
    //if ( (strncasecmp(name, CONNMGR_WLAN_IFNAME, strlen(CONNMGR_WLAN_IFNAME)) == 0) ||
    //     (strncasecmp(name, CONNMGR_WAN_IFNAME, strlen(CONNMGR_WAN_IFNAME)) == 0)  ||
    //     (strncasecmp(name, CONNMGR_ETH_IFNAME, strlen(CONNMGR_ETH_IFNAME)) == 0) )
    if ( (name != NULL) &&
         ((strncasecmp(name, cm_monitored_net[i=CM_MONITORED_WLAN_IDX].dev_name, strlen(cm_monitored_net[CM_MONITORED_WLAN_IDX].dev_name)) == 0) ||
         (strncasecmp(name, cm_monitored_net[i=CM_MONITORED_WAN_IDX].dev_name, strlen(cm_monitored_net[CM_MONITORED_WAN_IDX].dev_name)) == 0)    ||
         (strncasecmp(name, cm_monitored_net[i=CM_MONITORED_ETH_IDX].dev_name, strlen(cm_monitored_net[CM_MONITORED_ETH_IDX].dev_name)) == 0) ) )
    {
        /* matches this connection */
		AFLOG_DEBUG1 ("cm_util_parse_uevents:: found dev=%s", name);
        parse_uevent->mon_conn_p = &cm_monitored_net[i];

        if (strncasecmp(CM_UEVENT_ADD, recv_buffer, 3) == 0 ) {
              parse_uevent->action = CM_UEVENT_ADD;
              parse_uevent->iAction = CM_UEVENT_ACTION_ADD;
        }
        else if (strncasecmp(CM_UEVENT_REMOVE, recv_buffer, 6) == 0) {
            parse_uevent->action = CM_UEVENT_REMOVE;
            parse_uevent->iAction = CM_UEVENT_ACTION_REMOVE;
        }
        else if (strncasecmp(CM_UEVENT_CHANGE, recv_buffer, 6) == 0) {
            parse_uevent->action = CM_UEVENT_CHANGE;
            parse_uevent->iAction = CM_UEVENT_ACTION_CHANGE;
        }
    }
    return;
}


