/*
 * cache_ap_list.c
 *
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
#include <stddef.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

#include "common.h"
#include "wpa_manager.h"
#include "wifistad.h"
#include "af_log.h"


// it typically should be only one
#define WIFISTA_MAX_STA_COUNT           2

// used as a control for loop
#define WIFISTA_SAFE_CHECK_NUM_APS      200

extern void wifista_print_aps_list ();
extern uint8_t
prv_get_next_master(char **bssid, wifista_ap_t *ap, uint8_t *is_more);


// storing the ACCESS POINT from the scan result
// used to pass to Hubby when asked
wifista_ap_list_t  cached_ap_list;


/* wifista_reset_ap_list
 *
 * initialize the cached_ap_list.
 **/
void
wifista_reset_ap_list()
{
	cached_ap_list.ap_count = 0;
	memset(cached_ap_list.aps, 0, sizeof(cached_ap_list.aps));

	return;
}

wifista_ap_list_t *wifista_get_ap_list()
{
	return &cached_ap_list;

}


/**** utilities ******/

static uint8_t
wifista_util_is_sta_connected_to_ap(char *ssid)
{
    wpa_manager_t   *m = wifista_get_wpa_mgr();
    int             rc = 0;


    AFLOG_DEBUG3("wifista_util_is_sta_connected_to_ap:: ssid=%s, (associated=%d ssid=%s)",
                 ((ssid == NULL) ? "" : ssid), m->assoc_info.associated, m->assoc_info.ssid);

    if ((ssid != NULL) &&
        (m->assoc_info.associated) &&
        ((rc = strncasecmp(ssid, m->assoc_info.ssid, HUB_SSID_LEN)) == 0)) {
        return (1);
    }
    return 0;
}


/**
 * Given the AP's capabilities, deduce whether it supports security.
 *
 * The capabilities are strings obtained from wpa scan_results, and
 * typically looks like the example below:
 * tok[3] = [WPA-PSK-TKIP][WPA2-PSK-CCMP][ESS]
 *
 * If we get a capability that starts with WEP or WPA we assume
 * the access point has security
 */
#define ESS_STR_LEN    5
uint8_t
wifista_is_AP_support_sec(char *capabilities)
{
    if (capabilities == NULL) {
        return (0);
    }

    char *c = capabilities;
    while(*c) {
        if (*c == '[') {
            char *ce = c + 1;
            while (*ce != ']' && *ce != '\0') {
                ce++;
            }
            if (*ce == ']') {
                *ce++ = '\0';
            }
            if (!strncmp(c + 1, "WEP", 3) || !strncmp(c + 1, "WPA", 3)) {
                AFLOG_DEBUG3("capabilities=%s,s=1", capabilities);
                return 1;
            }
            c = ce;
        } else {
            c++;
        }
    }

    AFLOG_DEBUG3("capabilities=%s,s=0", capabilities);
    return (0);
}


/*
 * First the lowest rssi AP within the first given number of the list.
 *
 * return
 *     index of the AP with the lowest rssi in the given set of APs.
 */
static uint8_t
wifista_find_lowest_rssi_ap(wifista_ap_list_t   *ap_list_p,  // list of ap
                            uint8_t             first_num_aps)   // first
{
    uint8_t   worst_rssi_idx = 0;
    uint8_t   i;

    for (i=1; (i<first_num_aps && i<ap_list_p->ap_count && i<WIFISTA_MAX_APS); i++) {
        if (ap_list_p->aps[i].rssi < ap_list_p->aps[worst_rssi_idx].rssi) {
            worst_rssi_idx = i;
        }
    }

    AFLOG_INFO("wifista_find_lowest_rssi_ap:: first_num_aps=%d, found worst_rssi_idx=%d",
               first_num_aps, worst_rssi_idx);
    return (worst_rssi_idx);
}


/*
 * not found in the list, return (-1).  otherwise, return the index
 */
static int8_t
wifista_is_AP_in_list(wifista_ap_list_t  *ap_list_p,
                             const char         *ssid)
{
    uint8_t     i;

    if ((ap_list_p == NULL) || (ssid == NULL)) {
        return (-1);
    }

    for (i=0; i<ap_list_p->ap_count; i++) {
        AFLOG_DEBUG3("wifista_is_AP_in_list:: ssid[%d]=%s,len=%d ssid=%s, len=%d",
                   i, ap_list_p->aps[i].ssid, strlen(ap_list_p->aps[i].ssid),
                   ssid, strlen(ssid));

        if (strncmp(ap_list_p->aps[i].ssid, ssid, WIFISTA_SSID_LEN) == 0) {
            AFLOG_DEBUG3("wifista_is_AP_in_list:: found ssid=%s, idx=%d",  ssid, i);
            return (i);
        }
    }

    return (-1);
}


/*
 * retrieve the APs from a scan_result.
 *
 * Note: when it comes to wifi setup, the design gives priority
 * to the user who is trying to setup the wifi connection via the
 * mobile app because we want a good user experience.
 * This means that when the user's request could tramp the auto mode.
 *
 * if the setup_mode is USER_REQEUST, then we want to provide a list of
 * 32 APs based on the highest signal (ie. beset rssi value).
 */
int wifista_retrieve_APs (char *result, wifi_setup_mode_e  setup_mode)
{
    wpa_manager_t   *m = wifista_get_wpa_mgr();
    char            *bssid = NULL;
    uint8_t         is_more = 1;
    int             rc = -1;
    int             count = 0;
    int8_t          idx = -1;

    if ((result == NULL) || (m == NULL)) {
        AFLOG_ERR("wifista_retrieve_APs:: invalid input, result_NULL=%d, m_NULL=%d",
                  (result==NULL), (m==NULL));
        return (-1);
    }

    AFLOG_DEBUG3("wifista_retrieve_APs:: results=%s", result);

    // init the cached AP list
    wifista_reset_ap_list();
    while (is_more && (cached_ap_list.ap_count < WIFISTA_MAX_APS)
           && (count < WIFISTA_SAFE_CHECK_NUM_APS)) {// get bssid
        uint8_t  ap_exists = 0;

        rc = prv_get_next_master(&bssid, &cached_ap_list.aps[cached_ap_list.ap_count], &is_more);

        // let's use a simple algorithm for now: fill up the first 32 APs,
        // and if next AP has better rssi, then replace the worst one in the
        // first 23 APs.
        if ((rc == 0) && (bssid != NULL)) {
            AFLOG_DEBUG3("wifista_retrieve_APs:: bssid=%s, is_more=%d, iface_name=%s, associated bssid=%s",
                       bssid, is_more, m->ctrl_iface_name, m->assoc_info.bssid);
            strncpy(cached_ap_list.aps[cached_ap_list.ap_count].bssid, bssid, 17);
            cached_ap_list.aps[cached_ap_list.ap_count].connected_to_it =
                    wifista_util_is_sta_connected_to_ap(cached_ap_list.aps[cached_ap_list.ap_count].ssid);

            // Find an AP with the same ssid in the list. Take the one with better rssi
            if ((rc=wifista_is_AP_in_list(&cached_ap_list, cached_ap_list.aps[cached_ap_list.ap_count].ssid)) >= 0) {
                AFLOG_DEBUG3("wifista_retrieve_APs:: existing SSID=%s, idx =%d, ap_count=%d",
                           cached_ap_list.aps[cached_ap_list.ap_count].ssid, rc,
                           cached_ap_list.ap_count);

                if (cached_ap_list.aps[rc].rssi > cached_ap_list.aps[cached_ap_list.ap_count].rssi) {
                    memset(&cached_ap_list.aps[cached_ap_list.ap_count], 0, sizeof(wifista_ap_t));
                    continue;
                }
                else {
                    memcpy(&cached_ap_list.aps[rc], &cached_ap_list.aps[cached_ap_list.ap_count], sizeof(wifista_ap_t));
                    memset(&cached_ap_list.aps[cached_ap_list.ap_count], 0, sizeof(wifista_ap_t));
                    ap_exists = 1;
                }
            }

            if ((setup_mode == USER_REQUEST) && (cached_ap_list.ap_count >= HUB_MAX_APS)) {

                /*  We want the first 32 best signal-strength APs to send back to the user.
                 *  - Fill up the first 32 entries. On the 33rd entry, we find the lowest rssi in the
                 *  previous 32, and replace it if its signal strength is weaker than the current one.
                 */
                if (idx == -1) {
                    idx = wifista_find_lowest_rssi_ap(&cached_ap_list, HUB_MAX_APS);
                }

                if (cached_ap_list.aps[idx].rssi < cached_ap_list.aps[cached_ap_list.ap_count].rssi) {
                    wifista_ap_t    temp_ap;

                    // swap the idx, and cached_ap_list.ap_count locations
                    memset(&temp_ap, 0, sizeof(temp_ap));
                    memcpy(&temp_ap, &cached_ap_list.aps[cached_ap_list.ap_count], sizeof(wifista_ap_t));

                    memset(&cached_ap_list.aps[cached_ap_list.ap_count], 0, sizeof(wifista_ap_t));
                    memcpy(&cached_ap_list.aps[cached_ap_list.ap_count], &cached_ap_list.aps[idx],
                           sizeof(wifista_ap_t));

                    memset(&cached_ap_list.aps[idx], 0, sizeof(wifista_ap_t));
                    memcpy(&cached_ap_list.aps[idx], &temp_ap, sizeof(temp_ap));

                    // reset the idx for next AP we found
                    idx = -1;
                }
            }

            if (ap_exists == 0) {
                cached_ap_list.ap_count++;
            }
        }
        count++;
        AFLOG_DEBUG3("wifista_retrieve_APs:: is_more=%d, ap_count=%d, count=%d",
                   is_more, cached_ap_list.ap_count, count);
    }

    // DEBUG only - remove
    wifista_print_aps_list();
    return (rc);
}


/* Look through the cached ap list to find a bssid for the given bssid
 *
 * This can be called multiple times.  Each time when bssid is found, but it didn't
 * connect.  There could be another ssid that matches this ssid.
 */
char *wifista_find_bssid_in_ap_list(char *ssid)
{
    int  i;

    if (ssid) {
        for (i=0; i<HUB_MAX_APS; i++) {
            if (strncmp(ssid, cached_ap_list.aps[i].ssid, strlen(cached_ap_list.aps[i].ssid)) == 0) {
                return (cached_ap_list.aps[i].bssid);
            }
        }
    }

    // debug
    wifista_print_aps_list();
    return (NULL);
}


/*
 * wifista_print_aps_list
 */
void wifista_print_aps_list ()
{
    int i;

    AFLOG_INFO("cached_ap_list:");
    AFLOG_INFO("    ap_count = %d", cached_ap_list.ap_count);
    for (i=0; (i<cached_ap_list.ap_count && (i<WIFISTA_MAX_APS)); i++) {
        AFLOG_INFO("    bssid: %s  ssid: %s  rssi=%d  sec=%d, connected=%d",
                   cached_ap_list.aps[i].bssid,
                   cached_ap_list.aps[i].ssid,
                   cached_ap_list.aps[i].rssi,
                   cached_ap_list.aps[i].support_security,
                   cached_ap_list.aps[i].connected_to_it);
    }
    return;
}
