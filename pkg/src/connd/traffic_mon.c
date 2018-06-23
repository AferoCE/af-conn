/*
* traffic_mon.c
*
* This contains the code for monitoring the wifi traffic:
* - monitor and detect if the wifi connection is up.  If connmgr detects
*   the wifi connection (i.e traffic is down) is off, then it attempts
*   to switch over to use the LTE network connection via the wand.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <resolv.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <event.h>
#include <time.h>

#include "af_log.h"
#include "connmgr.h"
#include "traffic_mon.h"
#include "connmgr_util.h"
#include "connmgr_stats.h"
#include "connmgr_select_engine.h"
#include "connmgr_extract_dns.h"
#include "../include/hub_config.h"
#include "connmgr_attributes.h"
#include "connmgr_hub_opmode.h"
#include "../include/netcheck_async.h"


#define CM_RECOVERY_ATTEMPT_INTERVALS     (CONNMGR_DWD_INTERVALS * 2)

/* externs */
extern const char *NETCONN_STATUS_STR[];
extern void cm_set_itf_up(cm_conn_monitor_cb_t   *net_conn_p,
                          hub_netconn_status_t   new_status);
extern void cm_set_itf_down (cm_conn_monitor_cb_t   *net_conn_p,
                             hub_netconn_status_t   new_status);
extern void cm_netconn_up_detected(cm_conn_monitor_cb_t   *net_conn_p);



/* given a mask in uint32, return a netmask number
 * - count the bits that are 1
 */
static uint32_t  cm_calc_netmask_length(uint32_t   mask)
{
	int count;

	for (count=0; mask; count++) {
		mask &= mask - 1;  // clear the least significant bit set
	}
	AFLOG_DEBUG3("Netmask length is: %d ", count);
	return count;
}

/*
 * initialize pcap device to look for wifi traffic
 */
int
cm_conn_mon_init(struct event_base  *evBase, void *arg)
{
    char            errbuf[PCAP_ERRBUF_SIZE];
    char            *dev = NULL;
    int             pcapfd = -1;
    bpf_u_int32     maskp = 0;
    bpf_u_int32     netp  = 0;
    struct          bpf_program  fp;  /* hold compiled program */
    char            pcap_filter[256];
    pcap_t          *pcap_handle = NULL;
    cm_conn_monitor_cb_t  *conn_mon_p = NULL;


    if (arg == NULL) {
        AFLOG_ERR("cm_conn_mon_init:: arg NULL");
        return (-1);
    }
    conn_mon_p = (cm_conn_monitor_cb_t *)arg;
    dev = (char *)conn_mon_p->dev_name;
    AFLOG_INFO("cm_conn_mon_init::init pcap session for dev_name=%s", dev);


    /* ask pcap for the network address and mask of the device
     * Note: netp is the network, not the address of the interface.
     * pcap_findalldevs(..) can find all the interface and its addresses
     */
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) < 0) {
        AFLOG_ERR("cm_conn_mon_init::%s - failed to get addr, ** NOT IN USE **, err:%s", dev, errbuf);

        conn_mon_p->dev_link_status = NETCONN_STATUS_ITFDOWN_SU;
        return (-1);
    }
    netp = ntohl(netp);
    maskp = ntohl(maskp);
    AFLOG_DEBUG1("cm_conn_mon_init::dev=%s, netp=0x%0X, network=%d.%d.%d.%d, mask=%d.%d.%d.%d",
                 dev, netp,
                 (netp >>24) & 0xFF,  (netp >> 16) & 0xFF,  (netp >> 8) & 0xFF,  (netp & 0xFF),
                 (maskp>>24) & 0xFF, (maskp >> 16) & 0xFF, (maskp >> 8) & 0xFF, (maskp & 0xFF)
                );

    /* open the device to capture live traffic from wlan on this bento
     * snaplen = BUFSIZE (specifies the snapshot length to be set on the handle)
     * promisc= 0, meaning not promiscuous mode, so only packets in this host.
     **/
    pcap_handle = pcap_open_live(dev, BUFSIZ, 0, 100, errbuf);
    if (pcap_handle == NULL) {
        AFLOG_ERR("cm_conn_mon_init::Open device(%s) failed.  errbuf=%s", dev, errbuf);
        return (pcapfd);
    }

    /* Let's only monitoring the interface incoming packet. Incoming tells us whether
     * the connection is alive or dead.
     *
     * Note: if this is the bridge interface, let's not set the direction.
     *       we only interested DNS traffic (ie. src port 53)
     */
    if (conn_mon_p->my_idx != CM_MONITORED_BR_IDX) {
        if (pcap_setdirection(pcap_handle, PCAP_D_IN) < 0) {
            AFLOG_WARNING("cm_conn_mon_init::dev=%s, failed to set pkt monitoring direction(err=%s)",
                          dev, pcap_geterr(pcap_handle));
        }
    }

    if (pcap_setnonblock(pcap_handle, 1, errbuf) < 0) {
        AFLOG_WARNING("cm_conn_mon_init:dev:%s, set nonblocking failed, err=%s", dev, errbuf);
    }

    pcapfd = pcap_get_selectable_fd(pcap_handle);
    if (pcapfd < 0) {
        AFLOG_ERR("cm_conn_mon_init::dev=%s, pcap_get_seletable_fd failed", dev);
        connmgr_close_pcap_session(conn_mon_p->my_idx);
        return (-1);
    }

    /* Now we'll compile the filter expression*/
    memset(pcap_filter, 0, sizeof(pcap_filter));
    if (conn_mon_p->my_idx == CM_MONITORED_BR_IDX) {
        snprintf(pcap_filter, sizeof(pcap_filter), "%s", "src port 53");
    }
    else {
        int  mask_length = cm_calc_netmask_length(maskp);
        snprintf(pcap_filter, sizeof(pcap_filter),
             "(port 53) or ((not broadcast and not multicast) and (not src net %d.%d.%d.%d/%d) and (udp or ip or tcp or icmp))",
             (netp >>24) & 0xFF, (netp >> 16) & 0xFF,  (netp >> 8) & 0xFF, (netp & 0xFF), mask_length
            );
    }
    AFLOG_INFO("cm_conn_mon_init:dev=%s,filter used=%s", dev, pcap_filter);
    if (pcap_compile(pcap_handle, &fp, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        AFLOG_WARNING("cm_conn_mon_init:dev=%s,err=%s:Error calling pcap_compile", dev, pcap_geterr(pcap_handle));
    } else {
        /* set the filter */
        if (pcap_setfilter(pcap_handle, &fp) == -1) {
            connmgr_close_pcap_session(conn_mon_p->my_idx);
            AFLOG_ERR("cm_conn_mon_init:dev=%s,err=%s:Error setting pcap filter", dev, pcap_geterr(pcap_handle));
            return (-1);
        }
    }


    if (conn_mon_p->conn_pkt_capture_handler != NULL) {
        /* create an event to monitor the 'this' interface for incoming traffic */
        conn_mon_p->conn_mon_pcap_ev = event_new(CONNMGR_GET_EVBASE(), pcapfd, EV_READ | EV_PERSIST,
                                                 conn_mon_p->conn_pkt_capture_handler, (void *) conn_mon_p);
        if (conn_mon_p->conn_mon_pcap_ev == NULL) {
            AFLOG_ERR("cm_conn_mon_init:dev=%s:create wlan_mon_event failed", dev);
            connmgr_close_pcap_session(conn_mon_p->my_idx);
            return (-1);
        }
        event_add(conn_mon_p->conn_mon_pcap_ev, NULL);   // no timeout
    }
    else {
        AFLOG_WARNING("cm_conn_mon_init:dev=%s:pkt_capture_handler=NULL. NO NETMON",
                      conn_mon_p->dev_name);
    }

    /* get the monitored interface address */
    get_itf_ipaddr(conn_mon_p->dev_name, AF_INET,
                   &conn_mon_p->ipaddr[0],
                   sizeof(conn_mon_p->ipaddr));
    AFLOG_INFO("cm_conn_mon_init:dev=%s,ipaddr=%s:", dev, conn_mon_p->ipaddr);

    conn_mon_p->pcap_fd = pcapfd;
    conn_mon_p->pcap_handle = pcap_handle;

    /* interface is up with IP addr assigned, we don't know service is up */
    conn_mon_p->idle_count = 0;
    conn_mon_p->flags |= CM_MON_FLAGS_CONN_ACTIVE;
    time(&(conn_mon_p->start_uptime));

    if (conn_mon_p->my_idx == CM_MONITORED_BR_IDX) {
        conn_mon_p->dev_link_status = NETCONN_STATUS_ITFNOTSUPP_SX;
    }
    else if (conn_mon_p->my_idx == CM_MONITORED_WAN_IDX) {
        // for LTE connection, we assume service is up if its interface get an IP
        // We don't want sending echo through LTE since it cost money
        conn_mon_p->dev_link_status = NETCONN_STATUS_ITFUP_SS;
    }
    else {
        conn_mon_p->dev_link_status = NETCONN_STATUS_ITFUP_SU;
    }

    AFLOG_INFO("cm_conn_mon_init:dev=%s,inuse=%s,link_dev_status=%s(%d)",
               dev,
               ((conn_mon_p == CM_GET_INUSE_NETCONN_CB()) ? "TRUE":"FALSE"),
               NETCONN_STATUS_STR[conn_mon_p->dev_link_status],
               conn_mon_p->dev_link_status);

    return (pcapfd);
}


/*
 * capture_pkt
 *    handles reading and parsing the captured packet.
 *    Note: this is the callback function used by pcap_dispatch()
 *
 *    The log trace are most useful for debugging.
 *
 *    On of the main functionality of this routine is be able to identify
 *    the type of packet that we have just received.  And if we want to act
 *    on it, we could.  For example, we want to extract the DNS query reply
 *    records, and we are able to instrument the call to parse the data.
 *
 * parameters
 * user - user specified data if any
 * h    - pcap packet header
 * packetptr - pointer to the packet captured.
 *
 */
static void
capture_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *packetptr)
{
    struct ip* iphdr;
    struct icmphdr* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;
    char srcip[256], dstip[256];
    unsigned short id, seq;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_int16_t type = 0;
    uint16_t  sport = 0;

    eptr = (struct ether_header *) packetptr;
    type = ntohs (eptr->ether_type);

    // If there is an ARP or RARP message from the wireless
    // intranet, do this mean the network wireless connection is working?
    if (type == ETHERTYPE_ARP) {/* handle arp packet */
        AFLOG_DEBUG3("%s_ARP", __func__);
    } /* ignore */
    else if(type == ETHERTYPE_REVARP) {/* handle reverse arp packet */
        AFLOG_DEBUG3("%s_REVARP", __func__);
    } /* ignore */
    else if (type == ETHERTYPE_IP) {
        int header_size;

        packetptr += 14;  // moving forward pass the ethernet header.
        iphdr = (struct ip *) packetptr;
        strcpy(srcip, inet_ntoa(iphdr->ip_src));
        strcpy(dstip, inet_ntoa(iphdr->ip_dst));

        AFLOG_DEBUG3("%s_IP:h->len=%d,ip_p=%d,src=%s,dst=%s,id=%d,tos=0x%x,ttl=%d,ip_len=%d,dg_len=%d",
                     __func__,
                     h->len, iphdr->ip_p, srcip, dstip,
                     ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
                     4 * iphdr->ip_hl, ntohs(iphdr->ip_len));

        //header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

        packetptr += 4 * iphdr->ip_hl;
        switch (iphdr->ip_p) {
            case IPPROTO_TCP:
                tcphdr = (struct tcphdr *) packetptr;
                AFLOG_DEBUG2("%s_TCP:dev=%s,src=%s/%d,dst=%s/%d",
                             __func__,
                             ( (user == NULL) ? "Unknown" : (char *)user ),
                             srcip, ntohs(tcphdr->source),
                             dstip, ntohs(tcphdr->dest));

#if 0
                AFLOG_DEBUG3("CAPTURED_PACKET:: %s\n", iphdrInfo);
                AFLOG_DEBUG3("CAPTURED_PACKET:: %c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d",
                       (tcphdr->urg ? 'U' : '*'),
                       (tcphdr->ack ? 'A' : '*'),
                       (tcphdr->psh ? 'P' : '*'),
                       (tcphdr->rst ? 'R' : '*'),
                       (tcphdr->syn ? 'S' : '*'),
                       (tcphdr->fin ? 'F' : '*'),
                       ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
                       ntohs(tcphdr->window), 4 * tcphdr->doff);
#endif

                sport = ntohs(tcphdr->dest);
                // header_size = 14 + ( 4 * iphdr->ip_hl) + tcphdr->doff*4;
                header_size = tcphdr->doff*4;
                if (sport == NAMESERVER_PORT) {
                    AFLOG_DEBUG2("%s_TCP_DNS:header_size=%d,len=%d",
                                 __func__, header_size, iphdr->ip_len - header_size);
                    cm_extract_dns_rrec(packetptr + header_size, iphdr->ip_len - header_size, 0);
                }
                break;

            case IPPROTO_UDP:
                udphdr = (struct udphdr *) packetptr;
                sport = ntohs(udphdr->source);
                AFLOG_DEBUG2("%s_UDP:dev=%s,src=%s/%d,dst=%s/%d",
                             __func__,
                             ( (user == NULL) ? "Unknown" : (char *)user ),
                             srcip, sport,
                             dstip, ntohs(udphdr->dest));
                header_size = sizeof (struct udphdr);
                if (sport == NAMESERVER_PORT) {
                    AFLOG_DEBUG2("%s_UDP_DNS:header_size=%d,len=%d",
                               __func__,
                               header_size, udphdr->len);
                    cm_extract_dns_rrec(packetptr + header_size, udphdr->len - header_size, 0);
                }
                break;

            case IPPROTO_ICMP:
                icmphdr = (struct icmphdr *) packetptr;
                memcpy(&id, (u_char *) icmphdr + 4, 2);
                memcpy(&seq, (u_char *) icmphdr + 6, 2);
                AFLOG_DEBUG2("%s__ICMP:dev=%s,src=%s,dst=%s,type=%d,code=%d,id=%d,seq=%d",
                             __func__,
                             ( (user == NULL) ? "Uknown" : (char *)user ),
                             srcip, dstip, icmphdr->type, icmphdr->code, ntohs(id), ntohs(seq));
                break;
        }

    }
    else if (type == ETHERTYPE_IPV6 ) {
        AFLOG_DEBUG2("%s_IPV6", __func__);
    } /* ignored */

    return;
}

/* cm_handle_netitf_got_packet
 *
 * Handle the capture packet
 **/
void
cm_handle_netitf_got_packet (evutil_socket_t fd, short events, void *arg)
{
    cm_conn_monitor_cb_t    *conn_mon_p = NULL;


    if (arg == NULL) {
        AFLOG_ERR("cm_handle_netitf_got_packet:: conn monitor cb is NULL");
        return;
    }
    conn_mon_p = (cm_conn_monitor_cb_t *)arg;
    if (conn_mon_p->pcap_handle == NULL) {
        AFLOG_ERR("cm_handle_netitf_got_packet:: dev:%s Invalid pcap_handle - something is wrong",
                  conn_mon_p->dev_name);
        return;
    }


    if (events & EV_READ) {  // on capture or read
        /* capture 1 packet */
        /* do we care about the packet? Maybe just count it
         *
         * if we are using wan, then
         *     if wifi (wlan) has connectivity
         *          switch back to wlan
         * endif
         */

        uint32_t res = pcap_dispatch(conn_mon_p->pcap_handle,
                                     1,
                                     capture_pkt,
                                     (u_char *)conn_mon_p->dev_name);

        if (conn_mon_p->my_idx == CM_MONITORED_BR_IDX) {
            /* if this is the bridge interface, we don't want it do anything */
            return;
        }

        AFLOG_DEBUG3("cm_handle_netitf_got_packet:event=EV_READ,res=%d,name=%s,flags=%d,conn_mon_p=%p",
                     res, conn_mon_p->dev_name, conn_mon_p->flags, conn_mon_p);

        if (res == -1) {
            if ((conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {
                /* nothing to do */
                return;
            }
            AFLOG_WARNING("cm_handle_netitf_got_packet:pcap_dispatch_err=(%s),cm_netconn_count=%d",
                          pcap_geterr(conn_mon_p->pcap_handle), cm_netconn_count);

            cm_set_itf_down(conn_mon_p, NETCONN_STATUS_ITFDOWN_SU);
            connmgr_close_pcap_session(conn_mon_p->my_idx);

            /* "This" network interface just went down..... switch  */
            cm_check_update_inuse_netconn(NETCONN_STATUS_ITFDOWN_SU, conn_mon_p);
        }
        else if (res == 0) {
            // This could happen, if the read timeout when the packets are
            // destined for the OUT direction.
            AFLOG_DEBUG2("cm_handle_netitf_got_packet:: NO packet read");
        }
#if 0
        else if (res == 1) {
            AFLOG_DEBUG2("cm_handle_netitf_got_packet:dev=%s,flags=%d,link_status=%d:RESET IDLE COUNT",
                         conn_mon_p->dev_name,
                         conn_mon_p->flags,
                         conn_mon_p->dev_link_status);

            /* Fix for HUB-904. If we're connected to an active portal, we could get traffic */
            /* back during the ping "probationary period". If we do, we should ignore this   */
            /* traffic because it could be fake traffic from the active portal.              */
            /* If this network connection is happy reset its idle_count */
            if (conn_mon_p->idle_count < CONNMGR_DWD_CHECK_INTERVALS) {
                conn_mon_p->idle_count = 0;
            }

            if ((conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {
                /* This interface was not active. This means it just received some
                 * traffic from this connection.  Let's switch check to see if we
                 * should switch over to it
                 */
                AFLOG_DEBUG1("cm_handle_netitf_got_packet:dev=%s:packet detected on interface",
                             conn_mon_p->dev_name);

                cm_netconn_up_detected(conn_mon_p);

            }

            /* if there is pending attributes need to be sent, do it now */
            if ((CONNMGR_GET_ATTR_PENDING() == 1) &&
                (CM_GET_INUSE_NETCONN_CB() == conn_mon_p)) {
                // currently only network_type
                cm_attr_set_network_type();

                CONNMGR_SET_ATTR_PENDING(0);
            }
        }  // res == 1
#endif
    } // (event & EV_READ)
    else {
        AFLOG_WARNING("cm_handle_netitf_got_packet:: Event not handled");
    }
    return;
}

#define NETCHECK_TIMEOUT_MS 20000

// handle the results of the echo check in the timeout handler below
static void on_idle_ping_check(int error, void *context)
{
    cm_conn_monitor_cb_t *conn_mon_p = (cm_conn_monitor_cb_t *)context;
    if (conn_mon_p == NULL) {
        AFLOG_ERR("%s_context", __func__);
        return;
    }

    if (!error) {
        // The interface is up; reset the idle count
        conn_mon_p->idle_count = 0;

        if ((conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {
            /* This interface was not active. This means it just received some
             * traffic from this connection.  Let's switch check to see if we
             * should switch over to it
             */
            AFLOG_DEBUG1("%s_succeeded:dev=%s:", __func__, conn_mon_p->dev_name);

            cm_netconn_up_detected(conn_mon_p);

        }

#if 0
        // if we haven't reported that this interface is up, do it now
        if ((CONNMGR_GET_ATTR_PENDING() == 1) &&
            (CM_GET_INUSE_NETCONN_CB() == conn_mon_p)) {
            // currently only network_type
            cm_attr_set_network_type();

            CONNMGR_SET_ATTR_PENDING(0);
        }
#endif
    }
    connmgr_mon_increment_ping_stat(conn_mon_p->my_idx);
    conn_mon_p->flags &= ~CM_MON_FLAGS_IN_NETCHECK;
}

// handle the results of the echo check in the timeout handler below

static void on_idle_echo_check(int error, void *context)
{
    cm_conn_monitor_cb_t *conn_mon_p = (cm_conn_monitor_cb_t *)context;
    if (conn_mon_p == NULL) {
        AFLOG_ERR("%s_context", __func__);
        return;
    }

    if (!error) { // the interface is up; reset the idle count
        conn_mon_p->idle_count = 0;

        if ((conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {
            /* This interface was not active. This means it just received some
             * traffic from this connection.  Let's switch check to see if we
             * should switch over to it
             */
            AFLOG_DEBUG1("%s_succeeded:dev=%s:", __func__, conn_mon_p->dev_name);

            cm_netconn_up_detected(conn_mon_p);

        }

#if 0
        // if we haven't reported that this interface is up, do it now
        if ((CONNMGR_GET_ATTR_PENDING() == 1) &&
            (CM_GET_INUSE_NETCONN_CB() == conn_mon_p)) {
            // currently only network_type
            cm_attr_set_network_type();

            CONNMGR_SET_ATTR_PENDING(0);
        }
#endif

#if 0
        if (conn_mon_p->dev_link_status != NETCONN_STATUS_ITFUP_SS) {
            conn_mon_p->dev_link_status = NETCONN_STATUS_ITFUP_SS;

            // Let's see if we need to switch to this network
            cm_check_update_inuse_netconn(NETCONN_STATUS_ITFUP_SS, conn_mon_p);
        }
#endif

        conn_mon_p->flags &= ~CM_MON_FLAGS_IN_NETCHECK;
    } else {      // echo check failed
        AFLOG_DEBUG1("%s_echo_failed:error=%d:trying ping", __func__, error);

        /* Let's try ping just to make sure */
        int rc = check_network(CONNMGR_GET_EVBASE(), conn_mon_p->ipaddr, conn_mon_p->dev_name,
                               NETCHECK_USE_PING, on_idle_ping_check, conn_mon_p, NETCHECK_TIMEOUT_MS);
        if (rc < 0) {
            AFLOG_ERR("%s_check_network:errno=%d:check network unrecoverable failure", __func__, errno);
        }
    }

    connmgr_mon_increment_ping_stat(conn_mon_p->my_idx);
}

static void on_bring_up_echo_check(int error, void *context)
{
    cm_conn_monitor_cb_t *conn_mon_p = (cm_conn_monitor_cb_t *)context;
    if (conn_mon_p == NULL) {
        AFLOG_ERR("%s_context", __func__);
        return;
    }
    if (!error) { // This interface is alive
        if (((conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) && ((conn_mon_p->flags & CM_MON_FLAGS_PREV_ACTIVE) == 0))  {
            cm_set_itf_up(conn_mon_p, NETCONN_STATUS_ITFUP_SS);
            AFLOG_INFO("%s_alive:link_status=%s(%d):interface is alive", __func__,
                       NETCONN_STATUS_STR[conn_mon_p->dev_link_status], conn_mon_p->dev_link_status);
        }
        else {
            conn_mon_p->idle_count = 0;
            conn_mon_p->dev_link_status = NETCONN_STATUS_ITFUP_SS;
        }

        /* Let's see if we need to switch to this network */
        cm_check_update_inuse_netconn(NETCONN_STATUS_ITFUP_SS, conn_mon_p);
    } else {      // This interface is not alive
        if (conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) {
            conn_mon_p->dev_link_status = NETCONN_STATUS_ITFUP_SF;

            cm_check_update_inuse_netconn(NETCONN_STATUS_ITFUP_SF, conn_mon_p);
        }
    }

    connmgr_mon_increment_ping_stat(conn_mon_p->my_idx);
    conn_mon_p->flags &= ~CM_MON_FLAGS_IN_NETCHECK;
}

/*
 * cm_mon_tmout_handler
 *
 * Each interface has an idle timer. This is its idle timer event handler.
 * When the idle period expired, this handler is invoked.
 *
 * The idle timer is used to count the number of times that we have not heard
 * anything received from this interface.   Each time the 'idle timer' expires,
 * we update the counter (idle_count) by one.
 *
 * In the cm_handle_netitf_got_packet(), it monitors any incoming packets.  If it
 * receive a packet, we reset the idle_count.
 *
 * Now, beside incrementing the idle_count, its other major function is to
 * check and validate if the network connection is still 'up' when the specified
 * idle interval is reached.
 *
 * It declares the network connection is 'dead' when we can send and receive an
 * echo to the AFERO echo service (or ping fails as a second try).
 *
 * if it is dead, then we need to:
 *  a) inform the other daemon(s) that the connection is dead
 *  b) switch to a different interface (if this is the current INUSE interface)
 *  c) update the flags and statistics
 *
 */
void
cm_mon_tmout_handler (evutil_socket_t fd, short events, void *arg)
{
    cm_conn_monitor_cb_t   *conn_mon_p = NULL;


    conn_mon_p = (cm_conn_monitor_cb_t *)arg;
    if (conn_mon_p == NULL) {
        AFLOG_ERR("cm_mon_tmout_handler:: arg is NUL");
        return;
    }

    if (events & EV_TIMEOUT) {  // on timeout in second(s) interval

        // suspend the idle count if we're checking the network
        // the netcheck times out after NETCHECK_TIMEOUT_MS (20 sec)
        if (conn_mon_p->flags & CM_MON_FLAGS_IN_NETCHECK) {
            return;
        }

        /* Periodically print a log */
        if (conn_mon_p->idle_count % CONNMGR_DWD_CHECK_INTERVALS == (CONNMGR_DWD_CHECK_INTERVALS-1)) {
            AFLOG_DEBUG2("cm_mon_tmout_handler:itf=%s,flags=%d,link_status=%d,idle_count=%d,inuse_itf=%s,num_netconn=%d",
                         conn_mon_p->dev_name, conn_mon_p->flags,
                         conn_mon_p->dev_link_status, conn_mon_p->idle_count,
                         CM_GET_INUSE_NETCONN_CB()->dev_name,
                         cm_netconn_count);
        }

        // Increment the idle_count
        conn_mon_p->idle_count++;

        if (conn_mon_p->idle_count == CONNMGR_DWD_CHECK_INTERVALS) {
            /* The network interface is not up (ie. no ip, or link is down) */
            if ((conn_mon_p->dev_link_status == NETCONN_STATUS_ITFDOWN_SU) ||
                (conn_mon_p->dev_link_status == NETCONN_STATUS_ITFDOWN_SX) ||
                (conn_mon_p->dev_link_status == NETCONN_STATUS_ITFNOTSUPP_SX)) {

                AFLOG_DEBUG2("cm_mon_tmout_handler:itf=%s,dev_link_status=%s(%d):nothing to do",
                             conn_mon_p->dev_name,
                             NETCONN_STATUS_STR[conn_mon_p->dev_link_status],
                             conn_mon_p->dev_link_status);
                return;
            }

            /* we have not heard anything on "this" interface for a period. Send an 'echo'
             * if we receive reply
             *      the connection is good -> reset idle_count
             * else
             *     assuming that the network might be 'dead' and let's
             *     see if any ping reply packet might be received before
             *     the network is declared 'dead'.
             *
             * Note:
             * if this is the WAN(LTE) connection. Don't ping . It costs money.
             * We assume that if (wwan0) exists with IP, then we should have connectivity.
             */
            if (conn_mon_p->my_idx != CM_MONITORED_WAN_IDX) {
                // send an echo, which has two effects:
                // 1) check if network is alive
                // 2) put some traffic on the network
                int rc = check_network(CONNMGR_GET_EVBASE(), echo_service_host_p, conn_mon_p->dev_name,
                                       NETCHECK_USE_ECHO, on_idle_echo_check, conn_mon_p, NETCHECK_TIMEOUT_MS);
                if (rc < 0) {
                    AFLOG_ERR("%s_check_network:errno=%d:check network unrecoverable failure", __func__, errno);
                }
            } // !WAN
        }
        else if (conn_mon_p->idle_count >= CONNMGR_DWD_INTERVALS) {
            int   old_link_status = conn_mon_p->dev_link_status;

            // Declare this connection DEAD if it has not been declared.
            if (conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) {
                // the interface is UP, but service FAILED
                cm_set_itf_down(conn_mon_p, NETCONN_STATUS_ITFUP_SF);

                AFLOG_INFO("%s_link_down:device=%s,old_status=%s(%d),new_status=%s(%d):",
                           __func__, conn_mon_p->dev_name,
                           NETCONN_STATUS_STR[old_link_status], old_link_status,
                           NETCONN_STATUS_STR[conn_mon_p->dev_link_status], conn_mon_p->dev_link_status);

                if (conn_mon_p == CM_GET_INUSE_NETCONN_CB()) {
                    /* this is the current INUSE network, passing traffic network went down.
                     * Need to switchover
                     **/
                    cm_check_update_inuse_netconn(conn_mon_p->dev_link_status, conn_mon_p);
                }
            } else {
                /* periodically let's check to see if we could init the network device */
                if ( ((conn_mon_p->idle_count % CM_RECOVERY_ATTEMPT_INTERVALS) == 0) ||
                     (conn_mon_p->dev_link_status == NETCONN_STATUS_ITFUP_SU)) {
                    // set the previous active flag according to whether the connection is active
                    conn_mon_p->flags &= ~CM_MON_FLAGS_PREV_ACTIVE;
                    if (conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) {
                        conn_mon_p->flags |= CM_MON_FLAGS_PREV_ACTIVE;
                    }
                    if (conn_mon_p->pcap_handle == NULL) {
                        if (conn_mon_p->conn_init_func) {
                            conn_mon_p->conn_init_func(CONNMGR_GET_EVBASE(), arg);
                        }
                    }

                    if (conn_mon_p->pcap_handle != NULL) {
                        /* update the link status and increment monitored network counter */
                        if ((conn_mon_p->flags & CM_MON_FLAGS_CONN_ACTIVE) && ((conn_mon_p->flags & CM_MON_FLAGS_PREV_ACTIVE) == 0)) {
                            AFLOG_DEBUG1("%s_activate:dev=%s:link becomes active",
                                         __func__, conn_mon_p->dev_name);
                            cm_set_itf_up(conn_mon_p, NETCONN_STATUS_ITFUP_SU);
                        }

                        if ((conn_mon_p->conn_timer_event) && ((conn_mon_p->flags & CM_MON_FLAGS_PREV_ACTIVE)==0)) {
                            evtimer_add(conn_mon_p->conn_timer_event, &conn_mon_p->mon_tmout_val);
                        }

                        /* Let echo tells us that this interface is GOOD or not */
                        conn_mon_p->flags |= CM_MON_FLAGS_IN_NETCHECK;
                        int rc = check_network(CONNMGR_GET_EVBASE(), echo_service_host_p, conn_mon_p->dev_name,
                                               NETCHECK_USE_ECHO, on_bring_up_echo_check, conn_mon_p, NETCHECK_TIMEOUT_MS);
                        if (rc < 0) {
                            AFLOG_ERR("%s_netcheck:errno=%d:unrecoverable netcheck failure", __func__, errno);
                        }

                        if (old_link_status != conn_mon_p->dev_link_status) {
                            AFLOG_INFO("%s_link_up:device=%s,old_status=%s(%d),new_status=%s(%d):",
                                       __func__, conn_mon_p->dev_name,
                                       NETCONN_STATUS_STR[old_link_status], old_link_status,
                                       NETCONN_STATUS_STR[conn_mon_p->dev_link_status], conn_mon_p->dev_link_status);
                        }

                    }
                }
            }
        }

    }  // event == EV_TIMEOUT
    else  {
        AFLOG_WARNING("cm_mon_tmout_handler:event=%d:event not handled", events);
    }

    return;
}


/*
 * connmgr_close_pcap_session
 *  - close a pcap session
 */
void connmgr_close_pcap_session(uint8_t idx)
{
    AFLOG_DEBUG1("connmgr_close_pcap_session:: close pcap session for idx=%d", idx);

    if ((idx >=0) && (idx < CONNMGR_NUM_MONITORED_ITF) ) {
        if (cm_monitored_net[idx].conn_mon_pcap_ev) {
            event_del(cm_monitored_net[idx].conn_mon_pcap_ev);
            event_free(cm_monitored_net[idx].conn_mon_pcap_ev);

            cm_monitored_net[idx].conn_mon_pcap_ev = NULL;
        }

        if (cm_monitored_net[idx].pcap_handle) {
            pcap_close(cm_monitored_net[idx].pcap_handle);
            cm_monitored_net[idx].pcap_handle = NULL;

            cm_monitored_net[idx].pcap_fd = -1;
        }
    }
    return;
}


/* cm_on_recv_hotplug_events
 *
 * Event handler to handle hotplug event
 *
 * action = remove  ==> the connection on this itf will be down
 * action = add     ==> the connection on this int will be up
 *
 * Note:
 *
 **/
void
cm_on_recv_hotplug_events (evutil_socket_t fd, short events, void *arg)
{
    char                    recv_buffer[512];
    int                     len;
    cm_parse_uevent_t       parse_uevent;
    cm_conn_monitor_cb_t    *net_conn_p = NULL;


    AFLOG_DEBUG2("cm_on_recv_hotplug_events::events=0x%hx, fd=%d", events, fd);

    memset(recv_buffer, 0, sizeof(recv_buffer));
    len = recv(fd, recv_buffer, sizeof(recv_buffer), MSG_DONTWAIT);

    AFLOG_DEBUG2("cm_on_recv_hotplug_events::HOTPLUG recv_buffer - len=%d buf=%s",
                 len, recv_buffer);
    cm_util_parse_uevent(recv_buffer, len, &parse_uevent);
    net_conn_p = parse_uevent.mon_conn_p;
    if (net_conn_p == NULL) {
        return;
    }

    // OK - this should contains the uevent that we are interested in
    switch (parse_uevent.iAction) {
        case CM_UEVENT_ACTION_ADD:
            AFLOG_DEBUG1("cm_on_recv_hotplug_events:uevent=ADD,device=%s,flags=%d,link_status=%d:interface added event",
                         net_conn_p->dev_name,
                         net_conn_p->flags,
                         net_conn_p->dev_link_status);

            if ((net_conn_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {

                cm_netconn_up_detected(net_conn_p);

            }
            break;

        case CM_UEVENT_ACTION_REMOVE:
            AFLOG_DEBUG1("cm_on_recv_hotplug_events:uevent=REMOVE,device=%s,flags=%d,num_monitored=%d:interface removed event",
                         net_conn_p->dev_name,
                         net_conn_p->flags,
                         cm_netconn_count);

            if (net_conn_p->flags & CM_MON_FLAGS_CONN_ACTIVE) {
                int   old_link_status = net_conn_p->dev_link_status;

                /* Update the link status, conn_active, and cm_netconn_count */
                cm_set_itf_down(net_conn_p, NETCONN_STATUS_ITFDOWN_SU);

                /* close the packet monitor session if it is open */
                connmgr_close_pcap_session(net_conn_p->my_idx);

                AFLOG_INFO("link_down_hotplug:device=%s,old_link_status=%s(%d),new_link_status=%s(%d)",
                           net_conn_p->dev_name,
                           NETCONN_STATUS_STR[old_link_status], old_link_status,
                           NETCONN_STATUS_STR[net_conn_p->dev_link_status], net_conn_p->dev_link_status);

                cm_check_update_inuse_netconn(NETCONN_STATUS_ITFDOWN_SU, net_conn_p);
            }
            break;

        case CM_UEVENT_ACTION_CHANGE:
            AFLOG_WARNING("cm_on_recv_hotplug_events_change:device=%s:CHANGE uevent NOT HANDLED",
                          net_conn_p->dev_name);
            break;

        default:
            break;
    }
    return;
}


/*
 * cm_on_recv_netlink_route_events
 *
 * This routine handles a netlink route event (NETLINK_ROUTE), specifcally,
 * when the network interface is operational up (vs administratively), and down.
 *
 *  Note:
 *  - testing show route_events doesn't seemed to work properly for wireless
 *    interface (i.e wlan0).
 */
void
cm_on_recv_netlink_route_events (evutil_socket_t fd, short events, void *arg)
{
    char                    recv_buffer[4096];
    int                     len;
    cm_conn_monitor_cb_t    *net_conn_p = NULL;
    struct iovec iov = { recv_buffer, sizeof recv_buffer };
    struct sockaddr_nl snl;
    struct msghdr msg = { (void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0 };
    struct nlmsghdr *h;
    struct ifinfomsg *ifi;
    char   ifname[IF_NAMESIZE];


    AFLOG_DEBUG2("cm_on_recv_netlink_route_events::events=0x%hx, fd=%d", events, fd);

    memset(recv_buffer, 0, sizeof(recv_buffer));
    len = recvmsg(fd, &msg, MSG_DONTWAIT);
    AFLOG_DEBUG3("cm_on_recv_netlink_route_events:: recv_buffer - len=%d", len);
    if (len > 0) {
        // We need to handle more than one message per 'recvmsg'
        for (h = (struct nlmsghdr *)recv_buffer; NLMSG_OK (h, (unsigned int) len);
             h = NLMSG_NEXT (h, len))
        {
            //Finish reading or some kind of error
            if ((h->nlmsg_type == NLMSG_DONE) || (h->nlmsg_type == NLMSG_ERROR)) {
                return;
            }

            if (h->nlmsg_type == RTM_NEWLINK) {
                ifi = NLMSG_DATA (h);
                if_indextoname(ifi->ifi_index, ifname);
                AFLOG_DEBUG1("cm_on_recv_netlink_route_events:: ifi_flags=0x%hx, interface=%s - %s",
                             ifi->ifi_flags,
                             ifname, (ifi->ifi_flags & IFF_RUNNING) ? "UP" : "DOWN/OTHER");

                /* Check for eth0, wwan0, wlan0 (wireless)  */
                if ((net_conn_p = cm_find_monitored_net_obj(ifname)) != NULL) {

                    if (ifi->ifi_flags & IFF_RUNNING) {
                        if (net_conn_p->flags & CM_MON_FLAGS_CONN_ACTIVE) {  // active already
                            /* nothing to do */
                            return;
                        }

                        cm_netconn_up_detected(net_conn_p);

                        /* If this is the WAN connection:
                         * In a scenario where the network restarted (i.e /etc/init.d/networt restart),
                         * we don't have the idle timer mechanism to perform the recovery.  So, let's
                         * retry few times before giving up.
                         */
                        if (net_conn_p->my_idx == CM_MONITORED_WAN_IDX) {
                            int retry = 0;
                            while ((net_conn_p->pcap_handle == NULL) && (retry < 5)) {
                                sleep(3);
                                cm_netconn_up_detected(net_conn_p);
                                retry++;
                            }
                        }

                    }
                    else {   // no need to worry about itf down - this is done in tmout handler

                        if (((net_conn_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) && (net_conn_p->pcap_handle == NULL)) {
                            /* nothing to do, it has been taking care of */
                            return;
                        }

                        cm_set_itf_down(net_conn_p, NETCONN_STATUS_ITFDOWN_SU);

                        /* close the packet monitor session if it is open */
                        connmgr_close_pcap_session(net_conn_p->my_idx);

                        AFLOG_INFO("cm_on_recv_netlink_route_events:: Notify:%s status changed (Interface DOWN, Service Unknown)",
                                   ifname);

                        cm_check_update_inuse_netconn(NETCONN_STATUS_ITFDOWN_SU, net_conn_p);
                    }
                }
            }
            else if (h->nlmsg_type == RTM_NEWADDR) { // [HUB-813]
				struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(h);
                struct rtattr *rth = IFA_RTA(ifa);
                int       rtl = IFA_PAYLOAD(h);
				uint8_t   found = 0;


                memset(ifname, 0, sizeof(ifname));
                while (rtl && RTA_OK(rth, rtl)) {
				    AFLOG_DEBUG3("cm_on_recv_netlink_route_events:: rta_type=%d", rth->rta_type);
                    if (rth->rta_type == IFA_LOCAL) {  // IFA_LOCAL == 2
                        uint32_t ipaddr = htonl(*((uint32_t *)RTA_DATA(rth)));
                        if_indextoname(ifa->ifa_index, ifname);
                        AFLOG_DEBUG2("cm_on_recv_netlink_route_events::%s is now %d.%d.%d.%d\n", ifname,
                               (ipaddr >> 24) & 0xff, (ipaddr >> 16) & 0xff,
                               (ipaddr >> 8) & 0xff, ipaddr & 0xff);
						found = 1;
						break;
                    }
					rth = RTA_NEXT(rth, rtl);
                }

                AFLOG_DEBUG1("cm_on_recv_netlink_route_events::RTM_NEWADDR, ifname:%s", ifname);

				if (found && ((net_conn_p = cm_find_monitored_net_obj(ifname)) != NULL)) {
                    AFLOG_INFO("cm_on_recv_netlink_route_events::RTM_NEWADDR, call cm_netconn_up_detected:%s", ifname);
                    cm_netconn_up_detected(net_conn_p);
                }
			}
			else if (h->nlmsg_type == RTMGRP_IPV4_IFADDR) {
                 AFLOG_INFO("cm_on_recv_netlink_route_events:: RTMGRP_IPV4_IFADDR");
            }
        }
    }
}


/* utility: to help managing the counter, and flags related to interface UP
 *
 * Note:
 *    There is a chance that there might be a race condition.  If it happens,
 *    this might show up in cm_netconn_count incorrectly updated.
 * */
void cm_set_itf_up(cm_conn_monitor_cb_t   *net_conn_p,
                   hub_netconn_status_t   new_status)
{
    net_conn_p->flags |= CM_MON_FLAGS_CONN_ACTIVE;
    net_conn_p->dev_link_status = new_status;
    time(&(net_conn_p->start_uptime));


    // restart the idle_count every time when we detect the itf is UP.
    net_conn_p->idle_count  = 0;

    cm_netconn_count = cm_netconn_count + 1;
    AFLOG_DEBUG1("cm_set_itf_up:: dev:%s, status=%s(%d), cm_netconn_count:%d",
                 net_conn_p->dev_name,
                 NETCONN_STATUS_STR[new_status], new_status,
                 cm_netconn_count);

    /* Use the idx as an easy way to perform the check: is it wireless dev (wlan0)?
     * Let's see update the wifi operation mode.
     **/
    if (net_conn_p->my_idx == CM_MONITORED_WLAN_IDX) {
        cm_wifi_opmode = hub_wireless_opmode(NETIF_NAME(WIFIAP_INTERFACE_0));

        /* If this is the master BENTO, we want to capture the DNS packet to
         * punch holes in the FW (from the bridge interface). In case for some
         * reason, the WIFI bridge interface (i.e br-apnet) was not initialized.
         *
         * Correction action: not the best place, but it should be sufficient */
        if (cm_wifi_opmode == HUB_WIFI_OPMODE_MASTER) {
            if ((bridge_mon_p != NULL) &&
                (bridge_mon_p->pcap_handle == NULL) &&
                (bridge_mon_p->conn_init_func)) {

                /* let's init the bridge interface's pcap monitoring */
                bridge_mon_p->conn_init_func(CONNMGR_GET_EVBASE(), (void *)bridge_mon_p);
            }
        }
    }
}


/* utility: to help managing the counter, and flags related to interface 'DOWN' */
void cm_set_itf_down (cm_conn_monitor_cb_t   *net_conn_p,
                             hub_netconn_status_t   new_status)
{

    if (net_conn_p == NULL) {
        return;
    }

    if (net_conn_p->flags & CM_MON_FLAGS_CONN_ACTIVE) {
        cm_netconn_count = cm_netconn_count - 1;
        net_conn_p->flags &= ~CM_MON_FLAGS_CONN_ACTIVE;
    }
    net_conn_p->dev_link_status = new_status;

    AFLOG_DEBUG1("cm_set_itf_down:: dev:%s, status=%s(%d), cm_netconn_count:%d",
                 net_conn_p->dev_name,
                 NETCONN_STATUS_STR[new_status], new_status,
                 cm_netconn_count);

    if (net_conn_p->my_idx == CM_MONITORED_WLAN_IDX) {
        cm_wifi_opmode = hub_wireless_opmode(NETIF_NAME(WIFIAP_INTERFACE_0));
    }
}


/* wrapper for the code when detecting an interface up */
void cm_netconn_up_detected(cm_conn_monitor_cb_t   *net_conn_p)
{
    int old_status;


    if (net_conn_p == NULL)
        return;

    AFLOG_DEBUG1("cm_netconn_up_detected:dev=%s,flags=%d,link_status=%d,pcap_handle=%p",
                 net_conn_p->dev_name, net_conn_p->flags,
                 net_conn_p->dev_link_status, net_conn_p->pcap_handle);

    old_status = net_conn_p->dev_link_status;

    /* When this network went down or became dead, the device is generally
     * removed from the os.  As result, the pcap session is closed,
     * and pcap_hanle is set to NULL.
     * So, when we detect that the network is up again, let's re-init
     * the pcap session and set the flags accordingly.
     **/
    if (net_conn_p->pcap_handle == NULL) {
        /* try if we can bring up the pcap session, etc */
        if (net_conn_p->conn_init_func(CONNMGR_GET_EVBASE(), net_conn_p) > 0) {

            /* when it is the bridge or none monitored interface, do nothing */
            if ((net_conn_p->my_idx == CM_MONITORED_BR_IDX) ||
                (net_conn_p->mon_policy.priority == CM_MONITORING_PRI_NONE)) {
                goto netconn_done;
            }

            if (net_conn_p->my_idx == CM_MONITORED_WAN_IDX) {
                cm_set_itf_up(net_conn_p, NETCONN_STATUS_ITFUP_SS);
            }
            else {
                cm_set_itf_up(net_conn_p, NETCONN_STATUS_ITFUP_SU);
            }
            cm_check_update_inuse_netconn(net_conn_p->dev_link_status, net_conn_p);
        }
        else {
            net_conn_p->dev_link_status = NETCONN_STATUS_ITFDOWN_SX;
            net_conn_p->flags &= ~CM_MON_FLAGS_CONN_ACTIVE;

            // [HUB-813]
            // conn_init_func failed due to IPADDR not assigned yet. Wait for two monitor
            // timeout event (4 seconds), let's try init again in the cm_mon_tmout_handler().
            //
            // Note: using the idle_count to facility (recovery check) by setting the
            //   idle_count to be 2 intervals less than CM_RECOVERY_ATTEMPT_INTERVALS.
            net_conn_p->idle_count = (CONNMGR_DWD_INTERVALS + CM_RECOVERY_ATTEMPT_INTERVALS - 2);
        }
    }
    else {
        /* when it is the bridge or none monitored interface, do nothing */
        if ((net_conn_p->my_idx == CM_MONITORED_BR_IDX) ||
            (net_conn_p->mon_policy.priority == CM_MONITORING_PRI_NONE)) {
            goto netconn_done;
        }

        /* the pcap session is good - this means the dev is created, and has IP
         * assigned.  This could due to network not reachable - not heard for
         * awhile.
         */
        if ((net_conn_p->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {
            AFLOG_WARNING("cm_netconn_up_detected:%s - becomes active!", net_conn_p->dev_name);
            if (net_conn_p->my_idx == CM_MONITORED_WAN_IDX) {
                cm_set_itf_up(net_conn_p, NETCONN_STATUS_ITFUP_SS);
            }
            else {
                cm_set_itf_up(net_conn_p, NETCONN_STATUS_ITFUP_SU);
            }
            cm_check_update_inuse_netconn(net_conn_p->dev_link_status, net_conn_p);
        }
    }

    if (net_conn_p->conn_timer_event) { // idle timer
        evtimer_add(net_conn_p->conn_timer_event, &net_conn_p->mon_tmout_val);
    }

    AFLOG_INFO("link_up:device=%s,flags=%d,old_status=%s(%d),new_status=%s(%d)",
               net_conn_p->dev_name, net_conn_p->flags,
               NETCONN_STATUS_STR[old_status], old_status,
               NETCONN_STATUS_STR[net_conn_p->dev_link_status], net_conn_p->dev_link_status);

    if (old_status != net_conn_p->dev_link_status) {
        //cm_netconn_status_notify();
    }


netconn_done:
    /* every time the physical interface is up, firewall rules are reloaded.
     * Hence, we need to reset the dns_wl db, so we could 're-populate' the
     * whitelist as the dns_wl is smart not to config the rule if it has seen
     * the dns mapped IP address already.
     */
    if ((old_status == NETCONN_STATUS_ITFDOWN_SU) ||
        (old_status == NETCONN_STATUS_ITFDOWN_SX)) {
        cm_dns_reset_wl_entries();
    }
}
