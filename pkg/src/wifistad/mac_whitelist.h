/*
 * mac_whitelist.h
 *
 * This contains the definitions and data structures used for managing
 * the MAC whitelist.  The MAC whitelist refers to a list of Bento MAC
 * addresses that are connectible APs.
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 *
 */
#ifndef _MAC_WHITELIST_H_
#define _MAC_WHITELIST_H_

#define WIFISTAD_MAX_NUM_MACADDR        10
#define WIFISTAD_MACADDR_STRLEN         (17+1)


typedef struct {
    uint8_t     num_mac;
    char        macaddr[WIFISTAD_MAX_NUM_MACADDR][WIFISTAD_MACADDR_STRLEN];
} wifista_mac_wl_t;


/***
 * API to initialize the data attributes used to manage the MAC whitelist.
 */
extern
void wifistad_init_mac_wl();


/***
 * API to return the data contains the MAC whitelist.
 */
extern
wifista_mac_wl_t *wifistad_get_mac_wl();

/***
 * API to check if a specified mac address is in the MAC whitelist
 *
 * return
 *  0  if the specified MAC address is not in the MAC whitelist
 *  1  if the specified MAC address is in the MAC whitelist
 */
extern 
uint8_t wifista_is_mac_in_wl(char *macaddr);

#endif // _MAC_WHITELIST_H_
