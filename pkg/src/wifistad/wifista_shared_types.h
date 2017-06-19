/*
 * file wifista_shared_types.h
 *
 * File contains shared types used in ipc communication between daemons.
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */
#ifndef __WIFISTA_SHARED_TYPES_H__
#define __WIFISTA_SHARED_TYPES_H__

#define HUB_SSID_LEN 		32
#define HUB_WIFI_CRED_LEN	64
#define HUB_MAX_APS		20


// data structure defining an Access Point (AP)
typedef struct {
	char 		ssid[HUB_SSID_LEN + 1];
	int8_t		rssi;
	uint8_t		support_security;  // use security: wpa, psk?
	uint8_t		connected_to_it;   // bento currently connect to this ssid?
} hub_ap_t;


// IPC message: for sending the AP list
typedef struct {
	uint8_t   	num_aps;
	hub_ap_t    AP[HUB_MAX_APS];
} hub_ap_list_t;

#define MAX_HUB_AP_LIST_MSG_SIZE    (sizeof(hub_ap_list_t))


/* IPC message: the bento wifi setup credentials
 */
typedef struct {
	char  	ssid[HUB_SSID_LEN + 1];
	char    key[HUB_WIFI_CRED_LEN + 1];
} hub_wifi_cred_t;

#define MAX_HUB_WIFI_CRED_MSG_SIZE    (sizeof(hub_wifi_cred_t))

#endif // __WIFISTA_SHARED_TYPES_H__
