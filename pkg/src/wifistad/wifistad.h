/*
 *
 * This contains the definitions and data structures for the
 * connection manager (cm) daemon (connmgr).
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */


#ifndef _WIFISTAD_H_
#define _WIFISTAD_H_

#include "wpa_manager.h"
#include "wifista_shared_types.h"
#include "af_attr_client.h"

// #define WIFISTAD_NUM_ATTR_RANGE     1
// extern af_attr_range_t  wifistad_attr_range[WIFISTAD_NUM_ATTR_RANGE];


// Looking for AFERO AP
#define AFERO_MASTER_SSID       "_afero_"    // TODO - temp for now
#define AFERO_MASTER_PW         "4ce1aac59993fa076ba1bc395aec7a57"


#define WIFISTA_MAX_APS         100

// data structure of an Access Point (AP)
// - This is used to cache the AP list
typedef struct {
    char         bssid[WIFISTA_BSSID_LEN];
    char         ssid[HUB_SSID_LEN + 1];
    int32_t      rssi;
    uint8_t      support_security;  // use security: wpa, psk?
    uint8_t      connected_to_it;   // bento currently connect to this ssid?
} wifista_ap_t;

typedef struct {
    uint8_t         ap_count;
    wifista_ap_t    aps[WIFISTA_MAX_APS];
} wifista_ap_list_t;

// WIFI SETUP related externs
extern wifista_ap_list_t  cached_ap_list;

typedef struct {
    uint8_t prev_provisioned;
    char    *bssid;    // valid if previous provisioned
    char    ssid[HUB_SSID_LEN + 1];
    char    key[HUB_WIFI_CRED_LEN + 1];
} wifi_cred_t;


#define  AFERO_WIFI_FILE        "/afero_nv/.afero_wifi.txt"

// Wifi setup APIs

/* Loads credentials from file / HSM; returns 0 if successful, 1 if failed to open file, 2 if failed to read HSM */
extern int wifista_load_wifi_cred(void);
/* Returns by reference the cached credentials; returns 0 if successful, 1 if no cached credentials available */
extern int wifista_get_wifi_cred(wifi_cred_t *cred_p);
/* Stores new credentials by updating cache and writing through to file / HSM */
extern void wifista_store_wifi_cred(wifi_cred_t *cred_p);

extern void wifista_setup_send_rsp(wpa_wifi_setup_t  *wifi_setup_p);
extern void wifista_wpa_process_scan_results(char *scan_result_p);

extern void wifista_wpa_user_connect_AP(void *my_param, void *result);
extern char *wifista_find_bssid_in_ap_list(char *ssid);
extern uint8_t wifista_is_AP_support_sec(char *capabilities);
extern void wifistat_wpa_user_reconn(void *my_param, void *result);


// cached AP list APIs
extern void wifista_reset_ap_list();
extern int wifista_retrieve_APs (char *result,wifi_setup_mode_e);
extern wifista_ap_list_t *wifista_get_ap_list();


// mac whitelist APIs
extern uint8_t wifista_is_mac_in_wl(char *macaddr);


// attr callback functions
extern void wifistad_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context);
extern void wifistad_attr_on_owner_set(uint32_t attributeId, uint16_t setId, uint8_t *value, int length, void *context);
extern void wifistad_attr_on_get_request(uint32_t attributeId, uint16_t getId, void *context);
extern void wifistad_attr_on_open(int status, void *context);
extern void wifista_attr_on_set_finished(int status, uint32_t attributeId, void *context);

// misc
extern void wifistad_set_wifi_cfg_info(uint8_t has_cfg);
extern void wifistad_queue_netcheck(void);

#endif //_WIFISTAD_H_
