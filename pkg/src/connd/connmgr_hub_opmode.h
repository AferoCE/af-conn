/*
* connmgr_hub_opmode.h
*
* This contains the definitions for wifi operational mode
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/
#ifndef _CONNMGR_HUB_OPMODE_H_
#define _CONNMGR_HUB_OPMODE_H_


/* define the wifi setup operation mode for this hub */
typedef enum {
    HUB_WIFI_OPMODE_UNKNOWN = 0,
    HUB_WIFI_OPMODE_MASTER  = 1,
    HUB_WIFI_OPMODE_ADHOC   = 2,
    HUB_WIFI_OPMODE_CLIENT  = 3,
    HUB_WIFI_OPMODE_MONITOR = 4,
} hub_wireless_opmode_t;


#endif  // _CONNMGR_HUB_OPMODE_H_
