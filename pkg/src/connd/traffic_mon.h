/*
* traffic_mon.h
*
* This contains the definition for monitoring the wifi traffic:
* - monitor and detect if the wifi connection is up.  If connmgr detects
*   the wifi connection (i.e traffic is down) is off, then it attempts
*   to switch over to use the LTE network connection via the wand.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#ifndef _TRAFFIC_MON_H_
#define _TRAFFIC_MON_H_

#include "connmgr.h"


/* close wlan pcap session and the associate fd */
extern
void connmgr_close_pcap_session(uint8_t idx);


extern
void wlan_mon_tmout_handler (evutil_socket_t fd, short events, void *arg);


// ************************************************************
// new version
// ************************************************************
extern int 
cm_conn_mon_init(struct event_base *evBase, void *arg);

extern void 
cm_handle_netitf_got_packet (evutil_socket_t fd, short events, void *arg);

extern void 
cm_mon_tmout_handler (evutil_socket_t fd, short events, void *arg);

extern void
cm_on_recv_hotplug_events (evutil_socket_t fd, short events, void *arg);

extern void
cm_on_recv_netlink_route_events (evutil_socket_t fd, short events, void *arg);

//extern void
//cm_util_parse_uevent(char *recv_buffer, int  len, cm_parse_uevent_t *parse_uevent);

extern void
cm_mon_tmout_wan_handler (evutil_socket_t fd, short events, void *arg);
#endif // _TRAFFIC_MON_H_
