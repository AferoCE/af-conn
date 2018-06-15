/*
 * wifistad_attributes.c
 *
 * This contains the definitions and data structures used for managing
 * the callback functions use in the communication with attrd, as well
 * the set, get attribute functionality.
 *
 * Copyright (c) 2016-2018, Afero Inc. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>

#include "af_rpc.h"
#include "af_attr_client.h"

#include "wifistad.h"
#include "wpa_manager.h"
#include "af_log.h"
#include "af_util.h"
#include "afwp.h"
#include "build_info.h"
#include "../include/signal_tracker.h"

#define RSSI_REPORTING_PERIOD_SEC	10
#define NUM_RSSI_TO_AVERAGE			8
#define RSSI_DIFF_TO_REPORT			4

extern void wifistad_close();

// on notification
void wifistad_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{
	wpa_manager_t  *m = wifista_get_wpa_mgr();

	if ((value == NULL) || (length <= 0)) {
		AFLOG_ERR("%s_param:value_null=%d,length=%d", __func__, value==NULL, length);
		return;
	}

	AFLOG_DEBUG2("%s_info:attributeId=%d,value[0]=%d", __func__,attributeId,value[0]);
	switch (attributeId) {
		case AF_ATTR_ATTRD_REPORT_RSSI_CHANGES: //
			{
				uint8_t report_rssi_change = *value;
				if (report_rssi_change == 1) {  // activate periodic rssi reporting
					if (m->rpt_rssi_event) {
						struct timeval rpt_rssi_timeout = { RSSI_REPORTING_PERIOD_SEC, 0 };
						event_add(m->rpt_rssi_event, &rpt_rssi_timeout);
						sigtrack_clear(NUM_RSSI_TO_AVERAGE);
					}
					else {
						AFLOG_ERR("%s_rssi_event:event=NULL:invalid rpt_rssi_event", __func__);
					}
				}
				else {  // deactivate periodic rssi reporting
					if (m->rpt_rssi_event) {
						event_del(m->rpt_rssi_event);
					}
				}
			}
			break;

		case AF_ATTR_CONNMGR_NETWORK_TYPE:
			// do nothing currently (but.....)
			break;

		case AF_ATTR_HUBBY_COMMAND: {
				/* per Device Attribute Registry:
				 * Size = 4 Bytes
				 * This value will have a one byte command followed by parameters if any. The format
				 * of the last three bytes are dictated by the first byte. This will be used to send
				 * useful commands to Hachi like reboot. Current commands:
				 * 1 = Reboot (last three bytes are ignored)
				 * 2 = Clear user data - aka factory reset (last three bytes are ignored)
				 * 3 = Enter factory test mode   (NOT SUPPORTED BY HUB)
				 */
				int8_t rssi = 0;  // as not connected
				char *blank_str = " ";
				uint8_t command = value[0];
				AFLOG_INFO("%s_command:command=%d", __func__, command);
				if (command == 2) { // we handle only clear user data
					AFLOG_INFO("%s_factory_reset_1::factory reset; update we are to disconnect", __func__);
					// let's update the conclave service about these attributes:
					// ssid, wifi steady state, wifi setup state, rssi
					m->wifi_setup.setup_event = WPA_EVENT_ID_WIFI_CREDENTIALS;  //about wifi setup
					m->wifi_setup.setup_state = WIFI_STATE_NOTCONNECTED;
					wifista_setup_send_rsp(&m->wifi_setup);
					m->wifi_setup.setup_event = 0;  // reset it

					wifista_set_wifi_steady_state(WIFI_STATE_NOTCONNECTED);

					af_attr_set(AF_ATTR_WIFISTAD_WIFI_RSSI, (uint8_t *)&rssi, sizeof(uint8_t),
								wifista_attr_on_set_finished, NULL);

					af_attr_set(AF_ATTR_WIFISTAD_CONFIGURED_SSID, (uint8_t *)blank_str, 1,
								wifista_attr_on_set_finished, NULL);

					AFLOG_INFO("%s_factory_reset_2::factory reset; clear wifi user data", __func__);

					unlink(AFERO_WIFI_FILE);
					af_wp_set_passphrase((uint8_t *)"");

					wifistad_set_wifi_cfg_info(0);

					// remove the network -- this will disconnect from the AP
					sleep(2);
					wpa_manager_remove_network_async(NULL, NULL, m->assoc_info.id);
					sleep(2);
					// let's shutdown this properly
					wifistad_close ();

					exit(0); /* exit so that the watcher can start it afresh */
				}
			}
			break;

		default:
			AFLOG_WARNING("%s_unhandled:attribute=%d", __func__, attributeId);
			break;
	}
	return;
}

// on_owner_set
// another client has changed an attribute this client owns
// assume value - contains the key value pairs of ssid, and credentials.
void wifistad_attr_on_owner_set(uint32_t attributeId, uint16_t setId, uint8_t *value, int length, void *context)
{
	wifi_cred_t    *wifi_cred = NULL;
	wpa_manager_t  *m = wifista_get_wpa_mgr();
	int            err = 1;
	int            status = AF_ATTR_STATUS_OK;

	if (value == NULL) {
		AFLOG_ERR("%s_value_NULL", __func__);
		return;
	}

	AFLOG_DEBUG2("%s_attribute:attributeId=%d", __func__, attributeId);

	switch (attributeId) {
		case AF_ATTR_WIFISTAD_CREDS:
			wifi_cred = malloc (sizeof(wifi_cred_t));
			hub_wifi_cred_t   *hub_wifi_cred = (hub_wifi_cred_t *)value;
			uint8_t           len = strlen(hub_wifi_cred->key);
			if ((wifi_cred) && (m->wifi_setup.who_init_setup != USER_REQUEST)) {
				RESET_WIFI_SETUP(m,0);
				memset(wifi_cred, 0, sizeof(wifi_cred_t));
				memcpy(wifi_cred->ssid, hub_wifi_cred->ssid, HUB_SSID_LEN);
				memcpy(wifi_cred->key,  hub_wifi_cred->key, HUB_WIFI_CRED_LEN);

				AFLOG_INFO("%s_wifi_cred:ssid=%s:received Wi-Fi credentials; posting setup request",
							__func__, wifi_cred->ssid);
				WIFI_SETUP_CONNECT_AP(m, wifi_cred, m->assoc_info.id);

				// let's update the service with our setup state formost:
				// Note: in the scenario where we switch from one AP to another, we disconnect
				//    the first AP which may causes network outage if only wifi is available.
				m->wifi_setup.setup_state = WIFI_STATE_PENDING;
				wifista_setup_send_rsp(&m->wifi_setup);

				// also update the wifi steady state
				wifista_set_wifi_steady_state(WIFI_STATE_PENDING);

				wifista_wpa_post_event(WPA_EVENT_ID_WIFI_CREDENTIALS, (void *) wifi_cred);
				err = 0;
			}

			if (err) {
				if (wifi_cred == NULL) {
					AFLOG_ERR("%s_malloc", __func__);
				}
				else {
					AFLOG_ERR("%s_setup_failed:ssid=%s,key_len=%d:user setup failed",
							  __func__, hub_wifi_cred->ssid, len);
				}
				// set the WIFI_SETUP_STATE attribute so APPs can be notified.
				m->wifi_setup.setup_state =((len==0) ? WIFI_STATE_HANDSHAKEFAILED : WIFI_STATE_NOTCONNECTED);
				wifista_setup_send_rsp(&m->wifi_setup);

				//  free the allocated memory
				if (wifi_cred) {
					free (wifi_cred);
					wifi_cred = NULL;
				}
				RESET_WIFI_SETUP(m,1);
			}
			break;

		case AF_ATTR_WIFISTAD_DEBUG_LEVEL: {
			int8_t level = *(int8_t *)value;
			if (level < LOG_DEBUG_OFF) {
				level = LOG_DEBUG_OFF;
			}
			g_debugLevel = level;
			AFLOG_INFO("%s_debug_level:debug_level=%d", __func__, level);
			break;
		}

		default:
			AFLOG_ERR("%s_unhandled:attributeId=%d", __func__, attributeId);
			status = AF_ATTR_STATUS_NOT_IMPLEMENTED;
			break;

	} // switch

	int sendStatus = af_attr_send_set_response(status, setId);
	if (sendStatus != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("%s_set_send:sendStatus=%d,status=%d,setId=%d", __func__, sendStatus, status, setId);
	}
}

// on_set_finished
// For now - let's just log an error if set failed.
void wifista_attr_on_set_finished(int status, uint32_t attributeId, void *context)
{
	if (status != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("%s_status:attributeId=%d,status=%d", __func__, attributeId, status);
	}
}


// on_get_request
// another client has requested an attribute this client owns
void wifistad_attr_on_get_request(uint32_t attributeId, uint16_t getId, void *context)
{
	wpa_manager_t  *m = wifista_get_wpa_mgr();
	uint8_t		   len;

	AFLOG_INFO("%s_info:attribute=%d", __func__, attributeId);

	switch (attributeId) {
		case AF_ATTR_WIFISTAD_AP_LIST:
			// We just got a 'wifi scan request from the user', from Hubby
			WIFI_SETUP_SCAN_REQUEST(m);
			WIFI_SETUP_ATTR_CTX(m, attributeId, getId);
			wifista_wpa_post_event(WPA_EVENT_ID_WIFI_SCAN_REQUESTED, (void *)&(m->wifi_setup));
			break;

		case AF_ATTR_WIFISTAD_CONFIGURED_SSID:
			len = strlen(m->assoc_info.ssid);
			AFLOG_DEBUG2("%s_ssid:ssid=%s,len=%d", __func__, m->assoc_info.ssid, len);
			if (len > 0) {
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId,
										  (uint8_t *)&m->assoc_info.ssid[0], len);
			}
			else {
				char *blank_str = " ";
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)blank_str, 1);
			}
			break;

		case AF_ATTR_WIFISTAD_WIFI_RSSI: {
				int8_t rssi = wpa_get_conn_network_rssi();
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&rssi, sizeof(int8_t));
			}
			break;

		case AF_ATTR_WIFISTAD_WIFI_SETUP_STATE:  // only have meaning during wifi setup
			AFLOG_DEBUG2("%s_setup_state:setup_state=%d", __func__, m->wifi_setup.setup_state);
			af_attr_send_get_response(AF_ATTR_STATUS_OK, getId,
									  (uint8_t *)&m->wifi_setup.setup_state, sizeof(uint8_t));
			break;


		case AF_ATTR_WIFISTAD_WIFI_STEADY_STATE: // have meaning outside wifi setup
			AFLOG_DEBUG2("%s_steady_state:steady_state=%d", __func__, m->wifi_steady_state);
			af_attr_send_get_response(AF_ATTR_STATUS_OK, getId,
									  (uint8_t *)&m->wifi_steady_state, sizeof(uint8_t));
			break;

		case AF_ATTR_WIFISTAD_DEBUG_LEVEL : {
				int8_t level = g_debugLevel;
				AFLOG_INFO("%s_debug_level:debug_level=%d", __func__, level);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&level, sizeof(int8_t));
			}
			break;

		case AF_ATTR_WIFISTAD_REVISION :
			af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)REVISION, sizeof(REVISION));
			break;

		case AF_ATTR_WIFISTAD_WIFI_KEY_MGMT: {
			/* 0 - None
			*  1 - WPA PSK
			*  2 - WPA-EAP
			*  3 - IEEE 802.1X
			*/
				uint8_t  value = 0;
				if (strstr(m->assoc_info.key_mgmt, "PSK") != NULL) {
					value = 1;
				}
				else if (strstr(m->assoc_info.key_mgmt, "NONE") != NULL) {
					value = 0;
				}
				else if (strstr(m->assoc_info.key_mgmt, "EAP") != NULL) {
					value = 2;
				}
				else if (strstr(m->assoc_info.key_mgmt, "IEEE8021X") != NULL) {
					value = 3;
				}
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(int8_t));
			}
			break;

		case AF_ATTR_WIFISTAD_WIFI_PAIRWISE_CIPHER:
		case AF_ATTR_WIFISTAD_WIFI_GROUP_CIPHER: {
			/* - Group (multicast and broadcast) cipher
			 *    or
			 * - Pairwise (unicast) cipher
			 * Supported so far:
			 * 0 - None
			 * 1 - WEP 40 bit
			 * 2 - WEP 104 bit
			 * 3 - TKIP
			 * 4 - AES CCMP
			 */
				uint8_t  value = 0;
				char  *cipher_p = (attributeId == AF_ATTR_WIFISTAD_WIFI_GROUP_CIPHER) ?
								m->assoc_info.group_cipher : m->assoc_info.pairwise_cipher;

				if (strstr(cipher_p, "CCMP") != NULL) {
					value = 4;
				}
				else if (strstr(cipher_p, "TKIP") != NULL) {
					value = 3;
				}
				else if (strstr(cipher_p, "WEP104") != NULL) {
					value = 2;
				}
				else if (strstr(cipher_p, "WEP40") != NULL) {
					value = 1;
				}
				else if (strstr(cipher_p, "NONE") != NULL) {
					value = 0;
				}
				AFLOG_INFO("%s_cipher:attributeId=%d,cipher=%d", __func__, attributeId, value);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(int8_t));
			}
			break;

		default:
			af_attr_send_get_response(AF_ATTR_STATUS_ATTR_ID_NOT_FOUND, getId, (uint8_t *)"", 0);
			break;
	}

	return;
}


// the attribute client library either opened successfully or failed to open
void wifistad_attr_on_open(int status, void *context)
{
	if (status != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("%s_failed:status=%d", __func__, status);
	}
}


/* EV_TIMEOUT handler for report rssi
 */
void wifista_report_rssi_tmout_handler (evutil_socket_t fd, short events, void *arg)
{
	int rc;

	int8_t rssi = sigtrack_add(wpa_get_conn_network_rssi(), RSSI_DIFF_TO_REPORT);
	if (rssi) {
		/* RSSI is different enough to be reported */
		rc = af_attr_set(AF_ATTR_WIFISTAD_WIFI_RSSI, (uint8_t *)&rssi, sizeof(uint8_t),
						 wifista_attr_on_set_finished, NULL);
		if (rc != AF_ATTR_STATUS_OK) {
			AFLOG_ERR("%s_failed:rssi=%d,rc=%d", __func__, rssi, rc);
		}
	}
}


/* set the steady state and also send out a set to the other daemons know.
 */
void wifista_set_wifi_steady_state(uint8_t steady_state)
{
	wpa_manager_t  *m = wifista_get_wpa_mgr();
	static uint8_t reported_steady_state_pending = 0;


	AFLOG_DEBUG2("%s_info:old_steady_state=%d,new_steady_state=%d", __func__, m->wifi_steady_state, steady_state);


	/* -------------------------- */
	/* REPORT THE STEADY STATE    */
	/* -------------------------- */
	if (m->wifi_setup.who_init_setup != USER_REQUEST) {
		if ((steady_state <= WIFI_STATE_PENDING) && (reported_steady_state_pending == 1)) {
			// We have already send pending prior to this, but the wifi has not
			// been connected since sending the pending.  Don't transition to pending
			// when we restart reconnecting cycle again.
			return;
		}
	}

	if (m->wifi_steady_state != steady_state) {
		int rc;
		AFLOG_DEBUG2("%s_attr_set:wifi_steady_state=%d", __func__, steady_state);
		rc = af_attr_set(AF_ATTR_WIFISTAD_WIFI_STEADY_STATE, (uint8_t *)&steady_state, sizeof(uint8_t),
						 wifista_attr_on_set_finished, NULL);
		if (rc != AF_ATTR_STATUS_OK) {
			AFLOG_ERR("%s_failed:rc=%d,wifi_steady_state=%d", __func__, rc, steady_state);
		}

		if (m->wifi_setup.who_init_setup != USER_REQUEST) {
			if (steady_state == WIFI_STATE_PENDING) {
				reported_steady_state_pending = 1;
			}
			else if ((steady_state == WIFI_STATE_CONNECTED) || (steady_state == WIFI_STATE_ECHOFAILED)) {
				reported_steady_state_pending = 0;
			}
		}
	}

	m->wifi_steady_state = steady_state;
	return;
}

