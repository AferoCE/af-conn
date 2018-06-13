/*
* connmgr_util.h
*
* This contains the code implementation utilities or helper functions.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/
#ifndef _CONNMGR_UTIL_H_
#define _CONNMGR_UTIL_H_

#define CONNMGR_UTIL_PING_OK        (1)
#define CONNMGR_UTIL_PING_FAILED    (0)


extern
uint8_t connmgr_util_ping(char *ipaddr);

extern
int conn_prv_ping(const char *src_addr, const char *dst_addr, const char *itf_string);

extern
cm_conn_monitor_cb_t *
        cm_find_monitored_net_obj(const char *ifname);

/*
 * API to retrieve the IP address given a interface dev name
 */
extern
int get_itf_ipaddr(const char   *itf_name,
                    int          domain,  // AF_INET, AF_INET6
                    char         *ipaddr,
                    size_t       addr_len);


/* open netlink socket - listen to hotplug event */
extern
int  cm_open_netlink_socket ();

#endif  // _CONNMGR_UTIL_H_
