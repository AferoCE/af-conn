/*
* connmgr.c
*
* The connection manager (connmgr): is responsible for the following
* functionalities:
* - monitor and detect if the wifi connection is up.  If connmgr detects
*   the wifi connection (i.e traffic is down) is off, then it attempts
*   to switch over to use the LTE network connection via the wand.
* - we want to whitelist a set of Afero-based service access addresses
*   such that traffic is only allowed if its destination is one of these
*   specified 'whitelisted' addresses.
* - collect connection statistics: number of rx packets, number of tx packets
*   etc.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>
#include <syslog.h>
#include <event.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "af_ipc_common.h"
#include "af_ipc_server.h"
#include "af_log.h"
#define NETIF_NAMES_ALLOCATE
#include "connmgr.h"
#include "connmgr_attributes.h"
#include "traffic_mon.h"
#include "connmgr_stats.h"
#include "connmgr_util.h"
#include "connmgr_select_engine.h"
#include "connmgr_extract_dns.h"
#include "../include/hub_config.h"
#include "../include/hub_netconn_state.h"
#include "connmgr_attributes.h"
#include "connmgr_hub_opmode.h"
#include "af_util.h"


#define CONNMGR_IPC_SERVER_NAME     "IPC.CONNMGR"


/* Global variables */
struct event_base  *connmgr_evbase = NULL;
struct event       *hotplug_ev = NULL;
int                hotplug_fd  = -1;
struct event       *net_link_route_ev = NULL;
int                net_link_route_fd  = -1;
uint8_t            cm_netconn_count = 0;
uint32_t           cm_wifi_opmode = HUB_WIFI_OPMODE_UNKNOWN;


uint8_t            g_enable_fw = 1;  // enable firewall flag


// We need to send device attribute(s) to service/APPs (via hubby).
// However, during network transition, it takes time for the
// network to be ready.  So, let's set a flag, and wait until
// we got confirmation before sending it out.
uint8_t            attr_set_pending = 0;

/* Points to the current interface that pass traffic */
cm_conn_monitor_cb_t  *cm_itf_inuse_p = NULL;

#ifdef BUILD_TARGET_DEBUG
uint32_t            g_debugLevel = LOG_DEBUG1;
#else
uint32_t            g_debugLevel = LOG_DEBUG1;
#endif

/* data structure for managing network connection info */
cm_conn_monitor_cb_t cm_monitored_net[CONNMGR_NUM_MONITORED_ITF];

cm_conn_monitor_cb_t *eth_mon_p = &cm_monitored_net[CM_MONITORED_ETH_IDX];  // ethernet
cm_conn_monitor_cb_t *wlan_mon_p= &cm_monitored_net[CM_MONITORED_WLAN_IDX]; // wifi
cm_conn_monitor_cb_t *wan_mon_p = &cm_monitored_net[CM_MONITORED_WAN_IDX];  // wan
cm_conn_monitor_cb_t *bridge_mon_p = &cm_monitored_net[CM_MONITORED_BR_IDX];  // bridge

int32_t connmgr_conn_to_attrd(struct event_base *ev_base);
void connmgr_shutdown();

// express interested to attribute daemon that we are interested in the
// notification for the following attributes.
af_attr_range_t  connmgr_attr_range[] = {
    {0, 0}          // place holder value only
};


static void usage()
{
    printf("usage: connmgr [ -d ] \n");
    printf("    -d : Disable the Afero Firewall\n");
	printf("\n");
    printf("** By defualt, the Afero Firewall is enabled \n");
}

static int parse_options(int argc, char * argv[])
{
	int option = 0;
	int errflg = 0;

    while ((option = getopt(argc, argv, "d")) != -1) {
        switch (option) {
            case 'd':
				g_enable_fw = 0;
				break;

			default:
				errflg = 1;
				break;
		}
	}

	if (errflg) {
		usage();
		return (-1);
	}
	return (0);
}


extern const char REVISION[];
extern const char BUILD_DATE[];
/*
 * connmgr main
 */
int main(int argc, char *argv[])
{
    int     i;


	/* parse the input options if any */
	if (argc > 1) {
		if (parse_options(argc, argv) < 0) {
			return (-1);
		}
	}

    openlog("connmgr", LOG_PID, LOG_USER);

    AFLOG_INFO("start_connmgr:revision=%s,build_date=%s", REVISION, BUILD_DATE);

    if (NETIF_NAMES_GET() < 0) {
        AFLOG_WARNING("CONNMGR:: failed to get network interface names; using defaults");
    }

	/* let's setup the afero based firewall here */
    AFLOG_INFO("start_connmgr:Firewall is %s", (g_enable_fw==1)?"enabled":"disabled");
	if (g_enable_fw == 1) {
		/* setup the Afero Firewall */
		if (af_util_system("/usr/lib/af-conn/init_firewall.sh") < 0) {
			AFLOG_ERR("CONNMGR:: starting FIREWALL failed");
		}
		sleep(1);  // allow fw time to finish
	}


    /* initialization of stats*/
    connmgr_stats_db_init();

    /* Setup the netmon control data structure.
     * The monitoring cb should be initialized first.
     */
    cm_monitored_cb_init();

    /* init whitelist */
    if (cm_dns_init_wl_db() < 0) {
        AFLOG_ERR("CONNMGR:: failed to read the whitelist");
        return (-1);
    }

    /* init afero service environment based variables, etc */
    hub_config_service_env_init();
    cm_wifi_opmode = hub_wireless_opmode(NETIF_NAME(WIFIAP_INTERFACE_0));

    /* create base event */
    connmgr_evbase = event_base_new();
    if (connmgr_evbase == NULL) {
        AFLOG_ERR("CONNMGR::Unable to create evbase");
        return (-1);
    }

    if (connmgr_conn_to_attrd(connmgr_evbase) < 0 ) {
        goto connmgr_exit;
    }


    /* open netlink socket for listening to hotplug events */
    hotplug_fd = cm_open_netlink_socket(SOCK_DGRAM, NETLINK_KOBJECT_UEVENT, -1);
    if (hotplug_fd < 0) {
        AFLOG_ERR("CONNMGR:: Unable to open socket for hotplug event");
        goto connmgr_exit;
    }
    AFLOG_INFO("CONNMGR::hotplug netlink socket fd=%d", hotplug_fd);
    hotplug_ev = event_new(connmgr_evbase, hotplug_fd, (EV_READ | EV_PERSIST),
                           cm_on_recv_hotplug_events, NULL);
    if (hotplug_ev == NULL) {
        AFLOG_ERR("CONNMGR:: Create HOTPLUG on_recv event failed");
        goto connmgr_exit;
    }
    event_add(hotplug_ev, NULL);

    /* open a second netlink socket to listen to NETLINK_ROUTE events - itf up*/
    net_link_route_fd = cm_open_netlink_socket(SOCK_RAW,
                           NETLINK_ROUTE,
                           (RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTM_NEWADDR));
    if (net_link_route_fd < 0) {
        AFLOG_ERR("CONNMGR:: Unable to open socket for hotplug event");
        goto connmgr_exit;
    }
    AFLOG_INFO("CONNMGR:: NETLINK_ROUTE socket fd=%d", net_link_route_fd);
    net_link_route_ev = event_new(connmgr_evbase, net_link_route_fd,
                                  (EV_READ | EV_PERSIST),
                                  cm_on_recv_netlink_route_events,
                                  NULL);
    if (net_link_route_ev == NULL) {
        AFLOG_ERR("CONNMGR:: Create NETLINK_ROUTE on_recv event failed");
        goto connmgr_exit;
    }
    event_add(net_link_route_ev, NULL);


    /* create an independent timeout event */
    /* for the ethernet interface */
    for (i=0; i<CONNMGR_NUM_MONITORED_ITF; i++)  {
        /* For each network we want to monitor:
         * Setup the pcap sessions for monitoring the incoming packets
         */
        if (cm_monitored_net[i].conn_init_func != NULL) {
            cm_monitored_net[i].conn_init_func(connmgr_evbase, &cm_monitored_net[i]);
        }

        /* Setup the idle time event - count the number of idle intervals which is
         * used to check if the network connection is alive or 'dead'
         */
        if (cm_monitored_net[i].conn_mon_tmout_func != NULL) {
            cm_monitored_net[i].conn_timer_event = event_new(connmgr_evbase, -1, EV_TIMEOUT | EV_PERSIST,
                                                             cm_monitored_net[i].conn_mon_tmout_func,
                                                             (void *) &cm_monitored_net[i]);
            if (cm_monitored_net[i].conn_timer_event == NULL) {
                AFLOG_ERR("CONNMGR:: Dev:%s, Create mon_timer_event failed",
                          cm_monitored_net[i].dev_name);
                goto connmgr_exit;
            }
        }

        /* During init, let's only schedule the timer event if the interface is up*/
        if ((cm_monitored_net[i].dev_link_status >= NETCONN_STATUS_ITFUP_SU) &&
            (cm_monitored_net[i].mon_policy.priority != CM_MONITORING_PRI_NONE)) {
            cm_netconn_count = cm_netconn_count + 1;

            cm_check_update_inuse_netconn(cm_monitored_net[i].dev_link_status, &cm_monitored_net[i]);
            if (cm_monitored_net[i].conn_timer_event != NULL) {
                evtimer_add(cm_monitored_net[i].conn_timer_event, &cm_monitored_net[i].mon_tmout_val);
            }
        } else {
#if 0  // for test only
            if (i == CM_MONITORED_ETH_IDX) {
                AFLOG_INFO("CONNMGR:: DEBUG CONFIG - Ethernet not supported");
                cm_monitored_net[i].dev_link_status = NETCONN_STATUS_ITFNOTSUPP_SX;
            }
#endif
        }
    } // for


    if (CM_GET_INUSE_NETCONN_CB() != NULL) {
        if (af_util_system("/usr/lib/af-conn/switch_route.sh %s", cm_itf_inuse_p->dev_name) < 0) {
            AFLOG_ERR("CONNMGR:: Setting up route for NETWORK(%s) failed",
                      cm_itf_inuse_p->dev_name);
        }
    }


    AFLOG_INFO("CONNMGR:: Network INUSE=(dev:%s), num of connected network: %d",
               ((CM_GET_INUSE_NETCONN_CB() == NULL) ? "NULL" : CM_GET_INUSE_NETCONN_CB()->dev_name),
               cm_netconn_count);


    // Start the event loop
    if (event_base_dispatch(connmgr_evbase)) {
        AFLOG_ERR("CONNMGR::Error running event loop.\n");
    }


connmgr_exit:       /* clean up */
    AFLOG_INFO("CONNMGR::Service is shutting down");
    connmgr_shutdown();

    return EXIT_FAILURE; /* There's no clean exit for this daemon */
}

/* close down sockets and cleanup
 */
void connmgr_shutdown()
{
    int i;

    closelog();

    if (connmgr_evbase) {
        event_base_free(connmgr_evbase);
        connmgr_evbase = NULL;
    }

    /* clean up: DNS whitelist DB related stuff */
    cm_dns_wl_db_cleanup();


    /* clean up: close pcap session, cancel the timer, and free the event */
    for (i=0; i<CONNMGR_NUM_MONITORED_ITF; i++) {
        connmgr_close_pcap_session(i);

        if (cm_monitored_net[i].conn_timer_event) {
            event_del(cm_monitored_net[i].conn_timer_event);
            event_free(cm_monitored_net[i].conn_timer_event);
            cm_monitored_net[i].conn_timer_event = NULL;
        }
    }

    /* close hotplug netlink socket */
    if (hotplug_ev) {
        event_del(hotplug_ev);
        event_free(hotplug_ev);
        hotplug_ev = NULL;
    }

    if (hotplug_fd > 0) {
        close (hotplug_fd);
        hotplug_fd = -1;
    }

    if (net_link_route_ev) {
        event_del(net_link_route_ev);
        event_free(net_link_route_ev);
        net_link_route_ev = NULL;
    }

    if (net_link_route_fd > 0) {
        close(net_link_route_fd);
        net_link_route_fd = -1;
    }

    af_attr_close();
}

/* Initialize the data structure used to manage the network monitoring
 * functionality.
 */
void
cm_monitored_cb_init ()
{
    uint8_t         i;

    memset(cm_monitored_net, 0, sizeof(cm_monitored_net));

    for (i=0; i<CONNMGR_NUM_MONITORED_ITF; i++) {
        cm_monitored_net[i].idle_count  = 0;
        cm_monitored_net[i].flags = 0;
        //cm_monitored_net[i].dev_link_status = CM_DEV_STATUS_DOWN;
        cm_monitored_net[i].dev_link_status = NETCONN_STATUS_ITFDOWN_SU;

        cm_monitored_net[i].pcap_fd = -1;
        cm_monitored_net[i].pcap_handle = NULL;
        cm_monitored_net[i].conn_mon_pcap_ev = NULL;
        cm_monitored_net[i].conn_timer_event = NULL;

        cm_monitored_net[i].my_idx = i;

        /* initialize to their respective functions. Currently, all 'networks' uses the same funcs
         * Note:  this can be different for different interface
         * */
        cm_monitored_net[i].conn_init_func = cm_conn_mon_init;
        cm_monitored_net[i].conn_pkt_capture_handler = cm_handle_netitf_got_packet;
        cm_monitored_net[i].conn_mon_tmout_func = cm_mon_tmout_handler;

        /* This section allow you to set 'special' functionality than the default */
        switch (i) {
            case CM_MONITORED_ETH_IDX:
                /* device names for the interfaces */
                strncpy((char *)cm_monitored_net[i].dev_name, NETIF_NAME(ETH_INTERFACE_0), IFNAMSIZ);

                cm_monitored_net[i].mon_tmout_val.tv_sec  = CONNMGR_IDLE_PERIOD;
                cm_monitored_net[i].mon_tmout_val.tv_usec = 0;

                /* Setup the monitoring policy for ETHERNET connection
                 * if the ethernet is available, it would have the highest priority
                 */
                cm_monitored_net[i].mon_policy.conn_monitored = 1;
                cm_monitored_net[i].mon_policy.priority = CM_MONITORING_PRI_FIRST;
                cm_monitored_net[i].mon_policy.rule_table[0].inuse = 1;
                break;

            case CM_MONITORED_WLAN_IDX:
                strncpy((char *)cm_monitored_net[i].dev_name, NETIF_NAME(WIFISTA_INTERFACE_0), IFNAMSIZ);

                cm_monitored_net[i].mon_tmout_val.tv_sec  = CONNMGR_IDLE_PERIOD;
                cm_monitored_net[i].mon_tmout_val.tv_usec = 0;

                /* Setup the policy for WIFI connection monitoring
                 *  WIFI has a low priority than ethernet
                 * */
                cm_monitored_net[i].mon_policy.conn_monitored = 1;
                cm_monitored_net[i].mon_policy.priority = CM_MONITORING_PRI_SECOND;
                cm_monitored_net[i].mon_policy.rule_table[0].inuse = 1;
                break;

            case CM_MONITORED_WAN_IDX:
                /* this is our default interface to use when ALL others have failed
                 * So - set these conn_active and dev_link_status
                 */

                cm_monitored_net[i].conn_mon_tmout_func = NULL;

                cm_monitored_net[i].mon_tmout_val.tv_sec  = CONNMGR_IDLE_PERIOD;
                cm_monitored_net[i].mon_tmout_val.tv_usec = 0;

                strncpy((char *)cm_monitored_net[i].dev_name, NETIF_NAME(WAN_INTERFACE_0), IFNAMSIZ);

                /* Not monitored, as WAN is our least preferred interface for sending
                 * traffic as using WAN cost us money
                 */
                cm_monitored_net[i].mon_policy.conn_monitored = 0;
                cm_monitored_net[i].mon_policy.priority = CM_MONITORING_PRI_THIRD;
                cm_monitored_net[i].mon_policy.rule_table[0].inuse = 0;
                break;

            case CM_MONITORED_BR_IDX:
                // we only care pcap session to extract dns reply. no monitoring
                cm_monitored_net[i].dev_link_status = NETCONN_STATUS_ITFNOTSUPP_SX;

                cm_monitored_net[i].conn_mon_tmout_func = NULL;
                strncpy((char *)cm_monitored_net[i].dev_name, NETIF_NAME(BRIDGE_INTERFACE_0), IFNAMSIZ);

                cm_monitored_net[i].mon_policy.conn_monitored = 0;
                cm_monitored_net[i].mon_policy.priority = CM_MONITORING_PRI_NONE;
                cm_monitored_net[i].mon_policy.rule_table[0].inuse = 0;
                break;

            default:
                AFLOG_WARNING("cm_monitored_cb_init:No individual functionality set for index:%d", i);
        }
    }

    return;
}


/* connmgr_conn_to_attrd
 * - Make the connection to attribute daemon.
 */
int32_t connmgr_conn_to_attrd(struct event_base *ev_base)
{
    // connect to communicate with attrd
    int err = af_attr_open(connmgr_evbase, CONNMGR_IPC_SERVER_NAME,
                       0, &connmgr_attr_range[0],      // attribs interested
                       connmgr_attr_on_notify,      // notify callback
                       connmgr_attr_on_owner_set,   // owner set callback
                       connmgr_attr_on_get_request, // owner get callback
                       connmgr_attr_on_close,       // close callback
                       connmgr_attr_on_open,        // open callback
                       NULL);                       // context
    if (err != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("CONNMGR::Unable to init af_attr_open, err=%d", err);
        return (-1);
    }
    return (0);
}
