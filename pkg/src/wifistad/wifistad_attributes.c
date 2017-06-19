/*
 * wifistad_attr_callback.c
 *
 * This contains the definitions and data structures used for managing
 * the callback functions use in the communication with attrd, as well
 * the set, get attribute functionality.
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
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


// timeout value for report to
struct timeval   rpt_rssi_timeout = {10, 0};


// on notification
void wifistad_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{
	wpa_manager_t  *m = wifista_get_wpa_mgr();

	if (value == NULL) {
		AFLOG_ERR("wifistad_attr_on_notify:: invalid input=%p", value);
		return;
	}

	AFLOG_DEBUG2("wifistad_attr_on_notify:: attributeId=%d value=%s", attributeId, (char *)value);
	switch (attributeId) {
		case AF_ATTR_ATTRD_REPORT_RSSI_CHANGES: //
			{
				uint8_t  report_rssi_change = *value;
				if (report_rssi_change == 1) {  // activate periodic rssi reporting
					if (m->rpt_rssi_event) {
						event_add(m->rpt_rssi_event, &rpt_rssi_timeout);
					}
					else {
						AFLOG_ERR("wifistad_attr_on_notify:: invalid rpt_rssi event");
					}
				}
				else {  // deactivate periodic rssi reporting
					if (m->rpt_rssi_event) {
						event_del(m->rpt_rssi_event);
					}
				}
			}
			break;

		default:
			AFLOG_WARNING("wifistad_attr_on_notify:: unhandled attribute=%d", attributeId);
			break;
	}
	return;
}


// on_set:
// another client has changed an attribute this client owns
// assume value - contains the key value pairs of ssid, and credentials.
int wifistad_attr_on_owner_set(uint32_t attributeId, uint8_t *value, int length, void *context)
{
	wifi_cred_t    *wifi_cred = NULL;
	wpa_manager_t  *m = wifista_get_wpa_mgr();
	int            err = 1;
    int            status = AF_ATTR_STATUS_OK;

	if (value == NULL) {
		AFLOG_ERR("wifistad_attr_on_owner_set:: invalid value=%p", value);
		return AF_ATTR_STATUS_UNSPECIFIED;
	}


	AFLOG_DEBUG2("wifistad_attr_on_owner_set:: attributeId=%d value=%s", attributeId, (char *) value);

	switch (attributeId) {
		case AF_ATTR_WIFISTAD_CREDS:
			wifi_cred = malloc (sizeof(wifi_cred_t));
			hub_wifi_cred_t   *hub_wifi_cred = (hub_wifi_cred_t *)value;
			uint8_t           len = strlen(hub_wifi_cred->key);
			if ((wifi_cred) && (len > 0) &&
				(m->wifi_setup.who_init_setup != USER_REQUEST)) {
				RESET_WIFI_SETUP(m);
				memset(wifi_cred, 0, sizeof(wifi_cred_t));
				memcpy(wifi_cred->ssid, hub_wifi_cred->ssid, HUB_SSID_LEN);
				memcpy(wifi_cred->key,  hub_wifi_cred->key, HUB_WIFI_CRED_LEN);

				AFLOG_INFO("wifistad_attr_on_owner_set::Recv WIFI credential(%s), post WIFI setup request",
							wifi_cred->ssid);
				WIFI_SETUP_CONNECT_AP(m, wifi_cred, m->assoc_info.id);
				wifista_wpa_post_event(WPA_EVENT_ID_WIFI_CREDENTIALS, (void *) wifi_cred);
				err = 0;
			}

			if (err) {
				if (wifi_cred == NULL) {
					AFLOG_ERR("wifistad_attr_on_owner_set:: malloc failed");
				}
				else {
					AFLOG_ERR("wifistad_attr_on_owner_set:: User SETUP failed, ssid=%s key_len=%d",
							  hub_wifi_cred->ssid, len);
				}
				// set the WIFI_SETUP_STATE attribute so APPs can be notified.
				m->wifi_setup.setup_state =((len==0) ? WIFI_STATE_HANDSHAKEFAILED : WIFI_STATE_NOTCONNECTED);
				wifista_setup_send_rsp(&m->wifi_setup);

				//  free the allocated memory
				if (wifi_cred) {
					free (wifi_cred);
					wifi_cred = NULL;
				}
				RESET_WIFI_SETUP(m);
			}
			break;


		default:
			AFLOG_ERR("wifistad_attr_on_owner_set:: unhandled attributeId=%d", attributeId);
            status = AF_ATTR_STATUS_NOT_IMPLEMENTED;
			break;

	} // switch

	return status;
}


// on_set_finished
// For now - let's just log an error if set failed.
void wifista_attr_on_set_finished(int status, uint32_t attributeId, void *context)
{
	if (status != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("wifista_attr_on_set_finished:: attributeId=%d, status=%d",
				  attributeId, status);
	}

	return;
}


// on request
// another client has requested an attribute this client owns
void wifistad_attr_on_get_request(uint32_t attributeId, uint16_t getId, void *context)
{
	wpa_manager_t  *m = wifista_get_wpa_mgr();
	uint8_t 		len;

	AFLOG_INFO("wifistad_attr_on_get_request:: get request for attribute=%d", attributeId);

	switch (attributeId) {
		case AF_ATTR_WIFISTAD_AP_LIST:
			// We just got a 'wifi scan request from the user', from Hubby
			WIFI_SETUP_SCAN_REQUEST(m);
			WIFI_SETUP_ATTR_CTX(m, attributeId, getId);
			wifista_wpa_post_event(WPA_EVENT_ID_WIFI_SCAN_REQUESTED, (void *)&(m->wifi_setup));
			break;

		case AF_ATTR_WIFISTAD_CONFIGURED_SSID:
			len = strlen(m->assoc_info.ssid);
			AFLOG_DEBUG2("wifistad_attr_on_get_request::ssid=%s, len=%d", m->assoc_info.ssid, len);
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

		case AF_ATTR_WIFISTAD_WIFI_STEADY_STATE: // have meaning outside wifi setup
		case AF_ATTR_WIFISTAD_WIFI_SETUP_STATE:  // only have meaning during wifi setup
			AFLOG_DEBUG2("wifistad_attr_on_get_request:: reply steady_state=%d", m->wifi_steady_state);
			af_attr_send_get_response(AF_ATTR_STATUS_OK, getId,
									  (uint8_t *)&m->wifi_steady_state, sizeof(uint8_t));
			break;

		default:
			af_attr_send_get_response(AF_ATTR_STATUS_ATTR_ID_NOT_FOUND, getId, (uint8_t *)"", 0);
			break;
	}

	return;
}


//
// the attribute client library either opened successfully or failed to open
void wifistad_attr_on_open(int status, void *context)
{
	if (status != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("wifista_attr_on_open:: open failed, status=%d", status);
		return;
	}

	return;
}


/* EV_TIMEOUT handler for report rssi
 */
void wifista_report_rssi_tmout_handler (evutil_socket_t fd, short events, void *arg)
{
	int rc;

	int8_t rssi = wpa_get_conn_network_rssi();
	rc = af_attr_set(AF_ATTR_WIFISTAD_WIFI_RSSI, (uint8_t *)&rssi, sizeof(uint8_t),
					 wifista_attr_on_set_finished, NULL);
	if (rc != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("wifistad_report_rssi_change:: rssi reporting failed, rssi=%d", rssi);
	}
	return;
}


/* set the steady state and also send out a set to the other daemons know.
 */
void wifista_set_wifi_steady_state(uint8_t    steady_state)
{
	wpa_manager_t  *m = wifista_get_wpa_mgr();

	AFLOG_DEBUG2("wifista_set_wifi_steady_state:: %d -> %d", m->wifi_steady_state, steady_state);
	if (m->wifi_steady_state != steady_state) {
		int rc;

		rc = af_attr_set(AF_ATTR_WIFISTAD_WIFI_STEADY_STATE, (uint8_t *)&steady_state, sizeof(uint8_t),
						 wifista_attr_on_set_finished, NULL);
		if (rc != AF_ATTR_STATUS_OK) {
			AFLOG_ERR("wifistad_report_rssi_change:: set failed (WIFI_STEADY_STATE=%d)", steady_state);
		}
	}

	m->wifi_steady_state = steady_state;
	return;
}
