/*
 * wpa_wifi_setup.c
 *
 * This file contains code to setup wifi connectivity on the device (Bento).
 *
 * The design involves Hubby sending wifistad request to setup WIFI connection
 * to a specified AP by providing a selected SSID.
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>
#include <syslog.h>

#include "af_attr_client.h"
#include "af_rpc.h"

#include "wpa_ctrl.h"
#include "wifista_shared_types.h"
#include "wpa_manager.h"
#include "af_log.h"
#include "wifistad.h"
#include "afwp.h"


// Wifi setup is initiated when the daemon receives an 'ap list request'.
// - perform scan
// - scan_result available
// - extract the AP list
// - send the ap list to Hubby
// - wait for Hobby to send credentials
// - if receive credentials from Hubby
//   - attempt to connect
//            connect success -> done
//            else connected failed -> err msg
//   - timeout waiting
//        err msg


static wifi_cred_t s_wifiCredCache;
static int s_wifiCredCacheValid = 0;

/*
 * store the WIFI credentials to a file
 */
void
wifista_store_wifi_cred(wifi_cred_t *cred_p)
{
	FILE	*fp = NULL;

	s_wifiCredCacheValid = 0;

	if (cred_p == NULL) {
		AFLOG_ERR("wifista_store_wifi_cred:: Invalid input.  Save failed");
		return;
	}

	if (strlen(cred_p->ssid) <= 0) {
		AFLOG_WARNING("wifista_store_wifi_cred:: BAD credentials, ssid=%s", cred_p->ssid);
		return;
	}

	memcpy(&s_wifiCredCache, cred_p, sizeof(s_wifiCredCache));
	s_wifiCredCacheValid = 1;

	/* open the file to write, create it if it doesn't exist */
	AFLOG_DEBUG2("wifista_store_wifi_cred:: saving credentials for ssid=%s", cred_p->ssid);
	fp = fopen(AFERO_WIFI_FILE, "w+");
	if (fp == NULL) {
		AFLOG_WARNING("wifista_store_wifi_cred:: Unable to open credential file for write");
		return;
	}

	fprintf(fp, "%s", cred_p->ssid);
	fclose(fp);

	if (af_wp_set_passphrase((uint8_t *)cred_p->key)) {
		AFLOG_WARNING("wifista_store_wifi_cred:: Can't set passphrase; removing cred file");
		unlink(AFERO_WIFI_FILE);
	}
}

int
wifista_get_wifi_cred(wifi_cred_t *cred_p)
{
	/* check params */
	if (cred_p == NULL) {
		AFLOG_ERR("wifista_get_wifi_cred::cred_p_NULL=%d", cred_p == NULL);
		return 1;
	}

	/* copy if cache is valid */
	if (s_wifiCredCacheValid) {
		memcpy(cred_p, &s_wifiCredCache, sizeof(s_wifiCredCache));
		return 0;
	}

	AFLOG_DEBUG2("wifista_get_wifi_cred:s_wifiCredCacheValid=%d", s_wifiCredCacheValid);
	return 1;
}


/*
 * return
 *  0 successful
 *  1 failed to get SSID from file
 *  2 failed to get PSK from HSM
 */
int
wifista_load_wifi_cred(void)
{
	char line[64];
	int  rc;

	// open the file for read
	FILE *fp = fopen(AFERO_WIFI_FILE, "r");

	if (fp) {
		int  len;

		// read ssid
		AFLOG_INFO("wifista_load_wifi_cred:: read info");
		memset(line, 0, sizeof(line));
		if (fgets(line, sizeof(line), fp) != NULL) {
			len = strlen(line);
			AFLOG_DEBUG2("len=%d,line=%s", len, line);
			// remove trailing newline if it exists
			if (line[len - 1] == '\n') {
				len--;
			}
			// clamp the length to 32 characters
			if (len > WIFISTA_SSID_LEN) {
				len = WIFISTA_SSID_LEN;
			}
			strncpy(s_wifiCredCache.ssid, line, len);
			s_wifiCredCache.ssid[len] = '\0';

			fclose(fp);

			if (len > 0) {
				if (af_wp_get_passphrase((uint8_t *)s_wifiCredCache.key, sizeof(s_wifiCredCache.key))) {
					// can't get key
					rc = 2;
				} else {
					// got key successfully
					s_wifiCredCacheValid = 1;
					rc = 0;
				}
			} else {
				AFLOG_WARNING("wifista_load_wifi_cred:empty SSID");
				rc = 1;
			}
		} else {
			AFLOG_WARNING("wifista_load_wifi_cred:: read SSID failed");
			fclose(fp);
			rc = 1;
		}
	}
	else {
		AFLOG_WARNING("wifista_load_wifi_cred:: open failed");
		rc = 1;
	}

	AFLOG_DEBUG2("wifista_load_wifi_cred:: ssid=%s", s_wifiCredCache.ssid );
	return rc;
}


/**
 * wifista_setup_format_ap_list
 *
 * - number of APs (uint32_t)
 * - List of AP info, with attributes in the following order:
 * 		- ssid (char)
 * 		- rrsi (int32_t)
 * 		- supported_security (uint8_t)
 * 		- connected_to_it    (uint8_t)
 *
 * param:
 * buf - buffer user to format the ap list
 * msglen - on input, input buffer size
 *          on output, the formatted msg size
 */
static void
wifista_setup_format_ap_list (uint8_t *buf,  int32_t  *msglen)
{
	wifista_ap_list_t *ap_list_p = wifista_get_ap_list();  // cached list
	hub_ap_list_t *hub_ap_list_p = (hub_ap_list_t *) buf;
	int 			i;


	if (buf == NULL) {
		AFLOG_ERR("wifista_setup_format_ap_list:: invalid buf");
		*msglen = 0;
		return;
	}

	memset(buf, 0, sizeof(hub_ap_list_t));
	for (i=0; (i<ap_list_p->ap_count && i<HUB_MAX_APS); i++) {
		hub_ap_list_p->AP[i].connected_to_it  = ap_list_p->aps[i].connected_to_it;
		hub_ap_list_p->AP[i].support_security = ap_list_p->aps[i].support_security;
		hub_ap_list_p->AP[i].rssi             = ap_list_p->aps[i].rssi;
		strncpy(hub_ap_list_p->AP[i].ssid, ap_list_p->aps[i].ssid, HUB_SSID_LEN);
		hub_ap_list_p->num_aps ++;
	}

	*msglen = sizeof(ap_list_p->ap_count) + sizeof(hub_ap_t) * hub_ap_list_p->num_aps;
	AFLOG_INFO("wifista_setup_format_ap_list:: Sending a list of (%d) APs to service", hub_ap_list_p->num_aps);
	return;
}


/**
 * wifista_setup_send_rsp
 *
 * Used during wifi connection/setup process: Either to send
 * a) the AP_LIST or
 * b) the state (steady or setup)
 * (setup state: defined as the state during user wifi configuration process).
 */
void 
wifista_setup_send_rsp(wpa_wifi_setup_t  *wifi_setup_p)
{
	int status = 0;

	// Nothing we could do, let the app itself timeout.
	if (wifi_setup_p == NULL) {
		AFLOG_ERR("wpa_handle_wifi_setup_request:: invalid input, setup_p=%p",
				  wifi_setup_p);
		return;
	}

	AFLOG_DEBUG2("wpa_wifi_setup_send_resp:: event=%d ", wifi_setup_p->setup_event);
	AFLOG_DEBUG2("                           state=%d ", wifi_setup_p->setup_state);
	AFLOG_DEBUG2("                           netword_id=%d ", wifi_setup_p->network_id);
	AFLOG_DEBUG2("                           attributeId=%d ", wifi_setup_p->attributeId);
	AFLOG_DEBUG2("                           getId=%d ", wifi_setup_p->getId);

	switch (wifi_setup_p->setup_event) {
		case WPA_EVENT_ID_WIFI_SCAN_REQUESTED: {
				uint8_t buf[MAX_HUB_AP_LIST_MSG_SIZE + 1];
				int32_t msglen = MAX_HUB_AP_LIST_MSG_SIZE;

				// send the reply to ATTRD to pass along to the sender:
				// if we have a list of APs, then the APs info are sent. Otherwise, count = zero
				memset(buf, 0, sizeof(buf));
				wifista_setup_format_ap_list(buf, &msglen);

				AFLOG_DEBUG2("wpa_wifi_setup_send_resp:: send AP_LIST, msglen=%d", msglen);

				if (msglen > 0) { // everything works out OK
					af_attr_send_get_response(AF_ATTR_STATUS_OK,
											  wifi_setup_p->getId,
											  &buf[0], msglen);
				}
				else {
					af_attr_send_get_response(AF_ATTR_STATUS_BAD_DATA,
											  wifi_setup_p->getId,
											  &buf[0], 0);
					AFLOG_ERR("wifista_setup_send_rsp:: format ap_list msg failed, msglen=%d", msglen);
				}
			}
			break;


		case WPA_EVENT_ID_WIFI_CREDENTIALS: {
				// we have to treat this as an attribute "set" to attrd so Hubby can be notified.
			AFLOG_DEBUG2("wifista_setup_send_rsp:: sending (WIFI_SETUP_STATE=%d) update",
						 wifi_setup_p->setup_state);
				status = af_attr_set (AF_ATTR_WIFISTAD_WIFI_SETUP_STATE,
									  (uint8_t *)&wifi_setup_p->setup_state,
									  sizeof(wifi_setup_p->setup_state),
									  wifista_attr_on_set_finished,
									  NULL);
				if (status != AF_ATTR_STATUS_OK) {
					AFLOG_ERR("wifista_setup_send_rsp:: set WIFI_SETUP_STATE failed, status=%d", status);
				}
			}
			break;


		default:  
			break;
	}

	return;
}


/* We are attempting to connect to a AP.  The connection could be initiated
 * by USER or AUTOMATICALLy.
 *
 * my_param = cached_list_ap
 * result = network connected id from prv_op_configure_network
 */
void wifista_wpa_auto_connect_AP(void *my_param,  	// input
								 void *result)	 	// result from
{
	static uint16_t  	connecting_ap = 0;
	int					i;
	uint8_t				found = 0;
	wifista_ap_list_t   *ap_list_p = (wifista_ap_list_t *)my_param;
	uint32_t 			id = (int)result;


	if (my_param == NULL) {
		AFLOG_ERR("wiifsta_wpa_connect_AP:: invalid input, my_param=%p", my_param);
		return;
	}

	AFLOG_INFO("wifista_wpa_connect_AP:: id=%d, result=%p", id, result);
	/* We are done trying to connect, when
     * 1. Connected, or
     * 2. No more AP to try
     */
	if (id > 0) { // We have connected.
		AFLOG_INFO("wifista_wpa_connect_AP:: Connected to AP=(%s)",
					ap_list_p->aps[connecting_ap].ssid);
		return;
	}

	for (i=connecting_ap; i<ap_list_p->ap_count; i++) {
		if ( (strstr(ap_list_p->aps[i].bssid, AFERO_MASTER_SSID) != NULL) &&
			 (wifista_is_mac_in_wl(ap_list_p->aps[i].ssid)) ) {
			// found an AFERO based AP, let's try to connect
			AFLOG_INFO("wifista_wpa_connect_AP:: found AFERO AP, ssid=%s",
					   ap_list_p->aps[i].ssid);
			connecting_ap = i;
			found = 1;
			break;
		}
	}

	/* Found an AFERO AP, let's try to connect to it */
	if (found == 1) {
		// We are attempting to connect to the AP - indicating start
		wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *)WPA_CONN_RESULT_INIT);
		wpa_manager_configure_bssid_async(wifista_wpa_auto_connect_AP, my_param,
										  ap_list_p->aps[connecting_ap].ssid,
										  AFERO_MASTER_PW,
										  ap_list_p->aps[connecting_ap].bssid,
										  0);
	}
	else { // No more AP to try
		connecting_ap = 0;
		wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *)WPA_CONN_RESULT_NO_ID);
	}
	return;
}

/*
 *
 */
void wifista_wpa_process_scan_results(wpa_state_e  wpa_state,  char *scan_results_p)
{
	wpa_manager_t   *m = wifista_get_wpa_mgr();

	if ((scan_results_p == NULL)) {
		AFLOG_ERR("wifista_wpa_process_scan_results:: invalid input");
		return;
	}

	AFLOG_INFO("wifista_process_scan_results:: wpa_state=%d (%s), scan_result_p=%p, who=%d",
			   wpa_state, WPA_STATE_STR[wpa_state],
			   scan_results_p, m->wifi_setup.who_init_setup);
	if (m->wifi_setup.who_init_setup == INIT_NONE) {
		// do nothing
		wifista_ap_list_t *ap_list = wifista_get_ap_list();
		if ((ap_list) && (ap_list->ap_count > 0)) {
			return;
		}
	}

	// get the list of APs
	// wifista_retrieve_APs(scan_result_p);
	if (m->wifi_setup.who_init_setup == AUTO_CONNECT) {
		wifista_retrieve_APs(scan_results_p, AUTO_CONNECT);
		wifista_wpa_auto_connect_AP((void *)&cached_ap_list, (void *)0);
	}
	else if (m->wifi_setup.who_init_setup == USER_REQUEST) {
		wifista_retrieve_APs(scan_results_p, USER_REQUEST);

		wifista_setup_send_rsp(&m->wifi_setup);

		AFLOG_DEBUG2("wifista_wpa_process_scan_results: Done. RESET_WIFI_SETUP");
		RESET_WIFI_SETUP(m);
	}

	return;
}


/*
 * wifista_wpa_user_connect_AP
 */
void wifista_wpa_user_connect_AP(void *my_param,  // input
								 void *result)	  // result from
{
	static wifi_cred_t  *wCred_p = NULL;  // (wifi_cred_t *)my_param;
	char         		*bssid   = NULL;
	int32_t 	 		id = (int)result;


	if (my_param == NULL) {
		AFLOG_ERR("wiifsta_wpa_USER_connect_AP:: invalid input, my_param=%p", my_param);
		return;
	}

    wCred_p = (wifi_cred_t *)my_param;
	AFLOG_INFO("wifista_wpa_user_connect_AP::  (%s), network ID:%d",
			   wCred_p->ssid, id);

	/* connected to the AP. Do nothing */
	if (id > 0) {  // wait for connected event for confirmation
		wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *) id);
		return;
	}
	else if ((id < WPA_CONN_RESULT_INIT) && (id > WPA_CONN_RESULT_END))
	{
		/* We tried to reconnect - failed.  Exit */
		if (wCred_p->prev_provisioned == 1) {
			AFLOG_INFO("wifista_wpa_user_connect_AP:: WIFI reconn failed, id=%d", id);
		}
		else {
			AFLOG_INFO("wifista_wpa_user_connect_AP:: WIFI conn failed, id=%d", id);
		}
		wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *) id);
		return;
	}

	/* for previous provisioned AP, we might have the bssid */
	if (wCred_p->prev_provisioned == 1) {
		bssid = wCred_p->bssid;
		if (bssid == NULL) {
			bssid = wifista_find_bssid_in_ap_list(wCred_p->ssid);
		}
	} else {
		bssid = wifista_find_bssid_in_ap_list(wCred_p->ssid);
	}
	if (bssid) {
		AFLOG_INFO("wifista_wpa_user_connect_AP:: Async config network:ssid=%s, bssid=%s",
					wCred_p->ssid, bssid);
		wpa_manager_configure_bssid_async(wifista_wpa_user_connect_AP,
										  (void *) wCred_p, wCred_p->ssid,
										  wCred_p->key, bssid, 0);
	}
	else {
		AFLOG_INFO("wifista_wpa_USER_connect_AP:: Cannot find bssid for %s, need to revert?",
					wCred_p->ssid);
		wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *)WPA_CONN_RESULT_NO_ID);
	}

	return;
}


/* wifistat_wpa_user_reconn
 *
 * reconnect to a previous connected AP, with the provisioned
 * credentials.
 */
void wifistat_wpa_user_reconn(void *my_param, void *result)
{
	wifi_cred_t  *cred_p = NULL;
	wpa_manager_t   *m = wifista_get_wpa_mgr();

	if (my_param == NULL) {
		AFLOG_ERR("wifistat_wpa_user_reconn:: invalid input, my_param=%p", my_param);
		return;
	}

	cred_p = (wifi_cred_t *)my_param;
	AFLOG_DEBUG2("wifistat_wpa_user_reconn: Entering, associated=%d, prev_prov=%d",
				m->assoc_info.associated, cred_p->prev_provisioned);

	if ((m->assoc_info.associated == 0)  && (cred_p->prev_provisioned)) {
		cred_p->bssid = m->assoc_info.bssid;
		wifista_wpa_user_connect_AP((void *)cred_p, (void *) 0);
	}
	else {
		if (cred_p != NULL)
			free(cred_p);

		cred_p = NULL;
	}

	AFLOG_DEBUG2("wifistat_wpa_user_reconn: Exiting");
	return;
}
