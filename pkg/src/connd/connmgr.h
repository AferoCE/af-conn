/*
 *
 * This contains the definitions and data structures for the
 * connection manager (cm) daeamon (connmgr).
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */


#ifndef _CONNMGR_H_
#define _CONNMGR_H_

#include <net/if.h>
#include <pcap/pcap.h>

#include "traffic_mon.h"
#include "../include/hub_netconn_state.h"
#include "../include/netif_names.h"

/* network interface for wifi AP */
//#define CONNMGR_WIFI_AP_IFNAME       "wlan0-1"


/* network interfaces being monitored */
//#define CONNMGR_ETH_IFNAME          "eth0"
    #define CM_MONITORED_ETH_IDX        0
//#define CONNMGR_WLAN_IFNAME         "wlan0"
    #define CM_MONITORED_WLAN_IDX       1
//#define CONNMGR_WAN_IFNAME          "wwan0"
    #define CM_MONITORED_WAN_IDX        2
//#define CONNMGR_BR_IFNAME           "br-apnet"
    #define CM_MONITORED_BR_IDX         3

#define CONNMGR_LAST_MONITORED_IDX   CM_MONITORED_BR_IDX


/*
 * The number of interfaces available to be monitored.
 */
#define CONNMGR_NUM_MONITORED_ITF    (CONNMGR_LAST_MONITORED_IDX + 1)


/**
 * Dead network connection detection interval
 *   - after this intervals have elapsed, and we have not heard
 *     from the interface, then we declare the connection to be dead.
 **/
#define CONNMGR_DWD_INTERVALS        10
#define CONNMGR_DWD_CHECK_INTERVALS  8

// the timeout value
#define CONNMGR_IDLE_PERIOD          2    // second


/* connmgr evbase */
extern struct event_base  *connmgr_evbase;
#define CONNMGR_GET_EVBASE()   (connmgr_evbase)


extern uint8_t  attr_set_pending;
#define CONNMGR_GET_ATTR_PENDING()  (attr_set_pending)
#define CONNMGR_SET_ATTR_PENDING(pending)  (attr_set_pending = pending)


/* prototype for packet capture handler function */
typedef  void (*cm_handle_pkt_capture_func_t) (evutil_socket_t fd, short events, void *arg);

/* prototype for handle timeout event function */
typedef void (*cm_handle_monitor_tmout_func_t)(evutil_socket_t fd, short events, void *arg);

/* prototype for init function on a per interface bases */
typedef int (*cm_mon_init_func_t)(struct event_base *evBase, void *arg);




/* --------------- */
/* POLICY & RULES  */
/* --------------- */

// Don't quite know what this should be???
typedef struct cm_monitoring_rule {
    uint8_t         inuse;   // this rule is being used?
} cm_monitoring_rule_t;


/* define the policy */
typedef struct cm_monitoring_policy {
    uint8_t           conn_monitored;

#define CM_MONITORING_PRI_FIRST     1       // highest preference
#define CM_MONITORING_PRI_SECOND    2
#define CM_MONITORING_PRI_THIRD     3
#define CM_MONITORING_PRI_NONE      99

    uint8_t           priority;             //

#define CM_MONITORING_NUM_POLICY_RULES      1
    cm_monitoring_rule_t      rule_table[CM_MONITORING_NUM_POLICY_RULES];
} cm_monitoring_policy_t;


/* ----------------------- */
/* montoring control block */
/* ----------------------- */

/* control structure used by the connection monitor.
 * */
typedef struct cm_conn_monitor_struct  {
    const char      dev_name[IFNAMSIZ];
    char            ipaddr[INET_ADDRSTRLEN];  // interface ipv4 address
    hub_netconn_status_t  dev_link_status;

    uint32_t        idle_count;         // idle count
    uint8_t         conn_active;        // this network is currently being monitored
    time_t          start_uptime;       // start time when the interface is up
                                        // iff conn_active = 1

    int32_t         pcap_fd;            // connection pcap file descriptor
    pcap_t          *pcap_handle;
    struct event    *conn_mon_pcap_ev;
    struct event    *conn_timer_event;
    struct timeval  mon_tmout_val;

    uint8_t         my_idx;             // index in cm_monitor_net table

    cm_monitoring_policy_t          mon_policy;

    cm_mon_init_func_t              conn_init_func;
    cm_handle_pkt_capture_func_t    conn_pkt_capture_handler;
    cm_handle_monitor_tmout_func_t  conn_mon_tmout_func;
} cm_conn_monitor_cb_t;

/*
 * The currently inuse network interface
 */
extern cm_conn_monitor_cb_t  *cm_itf_inuse_p;
#define CM_GET_INUSE_NETCONN_CB()  (cm_itf_inuse_p)
#define CM_SET_INUSE_NETCONN_CB(cb_p)  (cm_itf_inuse_p = cb_p)


/*
 * Number of actively monitered network connections
 */
extern uint8_t     cm_netconn_count;

/*
 * Define the 'hotplug' event we want to handle
 */
#define CM_UEVENT_ACTION_ADD        1
#define CM_UEVENT_ACTION_REMOVE     2
#define CM_UEVENT_ACTION_CHANGE     3

typedef struct cm_parse_uevent {
    const char              *action;
    uint8_t                 iAction;
    cm_conn_monitor_cb_t    *mon_conn_p;
} cm_parse_uevent_t;

/*
 * define the control data for networks being monitored
 */
extern
cm_conn_monitor_cb_t cm_monitored_net[CONNMGR_NUM_MONITORED_ITF];

extern cm_conn_monitor_cb_t *eth_mon_p;
extern cm_conn_monitor_cb_t *wan_mon_p;
extern cm_conn_monitor_cb_t *wlan_mon_p;
extern cm_conn_monitor_cb_t *bridge_mon_p;

/* initialization function for the above connection monitoring cb */
extern
void cm_monitored_cb_init ();

extern
int cm_check_update_inuse_netconn(hub_netconn_status_t    trigger_ev,
                                  cm_conn_monitor_cb_t    *trigger_ev_conn_p);

extern void
cm_util_parse_uevent(char *recv_buffer, int  len, cm_parse_uevent_t *parse_uevent);

#endif //_CONNMGR_H_
