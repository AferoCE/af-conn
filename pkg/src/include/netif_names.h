/*
 * netif_names.h -- common connectivity definitions for getting network interfaces
 *
 * Copyright (c) 2017, Afero, Inc. All rights reserved.
 */

#ifndef __NETIF_NAMES_H__
#define __NETIF_NAMES_H__

#include "af_util.h"

#define __NETIF_DEFS \
    __NETIF_DEF(ETH_INTERFACE_0,eth0) \
    __NETIF_DEF(WIFISTA_INTERFACE_0,wlan0) \
    __NETIF_DEF(WAN_INTERFACE_0,wwan0) \
    __NETIF_DEF(WIFIAP_INTERFACE_0,wlan0-1) \
    __NETIF_DEF(BRIDGE_INTERFACE_0,br-apnet) \


#define __NETIF_DEF(_x,_y) _x,

enum {
    __NETIF_DEFS
    __NETIF_NUM_INTERFACES
};

#undef __NETIF_DEF

#ifdef NETIF_NAMES_ALLOCATE
#define __NETIF_DEF(_x,_y) { #_x, #_y },
af_key_value_pair_t g_netif_pairs[__NETIF_NUM_INTERFACES] = {
    __NETIF_DEFS
};
#undef __NETIF_DEF
#else
extern af_key_value_pair_t g_netif_pairs[__NETIF_NUM_INTERFACES];
#endif

#define NETIF_NAME(_x) (g_netif_pairs[_x].value)
#define NETIF_NAMES_GET() (af_util_parse_key_value_pair_file("/etc/af-conn/netif_names",g_netif_pairs,__NETIF_NUM_INTERFACES))

#endif // __NETIF_NAMES_H__
