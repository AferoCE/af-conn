/*
 * mac_whitelist.c
 *
 * This contains the definitions and data structures used for managing
 * the MAC whitelist.  The MAC whitelist refers to a list of Bento MAC
 * addresses that are connectible APs.
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>

#include "wpa_manager.h"
#include "mac_whitelist.h"
#include "af_log.h"


// BENTO MAC whitelist -- supported bento as APs
static wifista_mac_wl_t   bento_mac_wl;


/***
 * API to initialize the data attributes used to manage the MAC whitelist.
 */
void wifistad_init_mac_wl()
{
    memset(&bento_mac_wl, 0, sizeof(bento_mac_wl));

    /* temporary for testing */
    bento_mac_wl.num_mac = 3;


#if 1 // TEMP_TEST_DATA
    // clif's master bento
    strncpy(bento_mac_wl.macaddr[0], "92:6F:18:00:00:B9", (WIFISTAD_MACADDR_STRLEN - 1));
    // clif's extender bento
    strncpy(bento_mac_wl.macaddr[1], "92:6F:18:00:00:A1", (WIFISTAD_MACADDR_STRLEN - 1));
    // tplink router
    strncpy(bento_mac_wl.macaddr[1], "ec:08:6b:24:b4:6f", (WIFISTAD_MACADDR_STRLEN - 1));
#endif

    return;
}


/***
 * API to return the data contains the MAC whitelist.
 */
wifista_mac_wl_t *wifistad_get_mac_wl()
{
    return &bento_mac_wl;
}


/***
 * API to check if a specified mac address is in the MAC whitelist
 *
 * return
 *  0  if the specified MAC address is not in the MAC whitelist
 *  1  if the specified MAC address is in the MAC whitelist
 *     or if the whitelist is empty.
 *     (note: if the whitelist is empty, then we want try every APs
 *      found in the scan.)
 */
uint8_t wifista_is_mac_in_wl(char *macaddr)
{
    int i;

    if (macaddr == NULL) {
        return (0);
    }

	AFLOG_DEBUG3("wifista_is_mac_in_wl: macaddr=%s \n", macaddr);
	if (bento_mac_wl.num_mac == 0) {
		return (1);
	}

    //for (i=0; i<WIFISTAD_MAX_NUM_MACADDR; i++) {
    for (i=0; i<bento_mac_wl.num_mac; i++) {
		AFLOG_DEBUG3(" bento_mac_wl[%d].macaddr=%s \n", i, bento_mac_wl.macaddr[i]);
        if (strncasecmp(bento_mac_wl.macaddr[i], macaddr, (WIFISTAD_MACADDR_STRLEN - 1)) == 0) {
            return (1);
        }
    }
    return (0);
}
