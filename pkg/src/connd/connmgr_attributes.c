/*
 * connmgr_attributes.c
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
#include <event.h>

#include "af_rpc.h"
#include "connmgr.h"
#include "connmgr_attributes.h"

#include "af_log.h"

extern struct event_base  *connmgr_evbase;

extern uint32_t connmgr_conn_to_attrd(struct event_base *ev_base);
extern void connmgr_shutdown();


/* cm_get_network_type
 *
 * based on the selected INUSE network, return the network type
 */
static int8_t  cm_get_network_type()
{
	cm_conn_monitor_cb_t *conn_cb = CM_GET_INUSE_NETCONN_CB();

	if (conn_cb == NULL) {
		return (HUB_NETWORK_TYPE_NONE);
	}

	// When there is only one interface configured, and it went down
	// we don't necessary set the conn_cb to NULL, however, it is no longer
	// on this interface, and we should report as NONE.
	if (conn_cb->conn_active == 0) {
		return (HUB_NETWORK_TYPE_NONE);
	}
	else if (conn_cb->my_idx == CM_MONITORED_ETH_IDX) {
		return (HUB_NETWORK_TYPE_ETHERNET);
	}
	else if (conn_cb->my_idx == CM_MONITORED_WLAN_IDX) {
		return (HUB_NETWORK_TYPE_WLAN);
	}
	else if (conn_cb->my_idx == CM_MONITORED_WAN_IDX) {
		return (HUB_NETWORK_TYPE_WAN);
	}
	else {
		return (HUB_NETWORK_TYPE_NONE);
	}
}


/* set the steady state and also send out a set to the other daemons know.
 */
void cm_attr_set_network_type ()
{
	int8_t   net_type = cm_get_network_type();
	int32_t  rc;


	AFLOG_DEBUG1("cm_attr_set_network_type:: network_type=%d", net_type);
	rc = af_attr_set(AF_ATTR_CONNMGR_NETWORK_TYPE, (uint8_t *)&net_type, sizeof(int8_t),
					connmgr_attr_on_set_finished, NULL);
	if (rc != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("cm_attr_set_network_type:: set failed for (NETWORK_TYPE=%d)", net_type);
	}
	return;
}


// on notification
void connmgr_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{

	if (value == NULL) {
		AFLOG_ERR("connmgr_attr_on_notify:: invalid input=%p", value);
		return;
	}

	AFLOG_DEBUG2("connmgr_attr_on_notify:: attributeId=%d, length=%d", attributeId, length);
	switch (attributeId) {
		default:
			AFLOG_WARNING("connmgr_attr_on_notify:: unhandled attribute=%d", attributeId);
			break;
	}
	return;
}


// on_set:
// another client has changed an attribute this client owns
// assume value - contains the key value pairs of ssid, and credentials.
int connmgr_attr_on_owner_set(uint32_t attributeId, uint8_t *value, int length, void *context)
{
    int status = AF_ATTR_STATUS_OK;

	if (value == NULL) {
		AFLOG_ERR("connmgr_attr_on_owner_set:: invalid value=%p", value);
		return AF_ATTR_STATUS_UNSPECIFIED;
	}


	AFLOG_DEBUG2("connmgr_attr_on_owner_set:: attributeId=%d value=%s", attributeId, (char *) value);

	switch (attributeId) {
		case AF_ATTR_CONNMGR_DEBUG_LEVEL: {
			int8_t level = *(int8_t *)value;
			if (level < LOG_DEBUG_OFF) {
				level = LOG_DEBUG_OFF;
			}
			g_debugLevel = level;
			AFLOG_INFO("connmgr_attr_on_owner_set:i debug_level=%d", level);
			break;
		}

		default:
			AFLOG_ERR("connmgr_attr_on_owner_set:: unhandled attributeId=%d", attributeId);
            status = AF_ATTR_STATUS_NOT_IMPLEMENTED;
			break;

	} // switch

	return status;
}


// on_set_finished
// For now - let's just log an error if set failed.
void connmgr_attr_on_set_finished(int status, uint32_t attributeId, void *context)
{
	if (status != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("connmgr_attr_on_set_finished:: attributeId=%d, status=%d",
				  attributeId, status);
	}

	return;
}


// on request
// another client has requested an attribute this client owns
void connmgr_attr_on_get_request(uint32_t attributeId, uint16_t getId, void *context)
{
	int8_t			value;


	AFLOG_INFO("connmgr_attr_on_get_request:: get request for attribute=%d", attributeId);

	switch (attributeId) {
		case AF_ATTR_CONNMGR_NETWORK_TYPE:
			value = cm_get_network_type();
			af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(int8_t));
			break;

        case AF_ATTR_CONNMGR_DEBUG_LEVEL:
            value = g_debugLevel;
            AFLOG_INFO("connmgr_attr_on_get_request: debug_level=%d", value);
            af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(int8_t));
            break;

		default:
			af_attr_send_get_response(AF_ATTR_STATUS_ATTR_ID_NOT_FOUND, getId, (uint8_t *)"", 0);
			break;
	}

	return;
}


// on_open
// the attribute client library either opened successfully or failed to open
void connmgr_attr_on_open(int status, void *context)
{
	if (status != AF_ATTR_STATUS_OK) {
		/* absolutely need to connect.  otherwise, we are useless */
		AFLOG_ERR("connmgr_attr_on_open:: open failed, status=%d", status);
		exit(-2);
	}

	// after initialization, let's send the network_type
	cm_attr_set_network_type();

	return;
}


/* connmgr_reconn_to_attrd
 *  - attempt to reconnect to attrd after a waiting period.  The waiting
 *    is 10 sec
 */
void connmgr_reconn_to_attrd(evutil_socket_t fd, short events, void *arg)
{
    int rc = -1;
    struct event_base *base = (struct event_base *)arg;

    if (base) {
        AFLOG_INFO("connmgr_reconn_to_attrd:: reconnecting");
        rc = connmgr_conn_to_attrd(base);
        if (rc < 0) {
            connmgr_attr_on_close(AF_ATTR_STATUS_OK, NULL);
        }
    }
    else {
        AFLOG_ERR("connmgr_reconn_to_attrd:: event_base went bonkers.exit");

        connmgr_shutdown();
        exit(-1);
    }
}


// connmgr_attr_on_close
//
// When the attrd daemon closed, freed as a client, closed its connection too.
// However, the freed needs to connect to attrd in order to work properly
// with its attributes.
//
// Try to reconnect to it after a period of time.
//
void connmgr_attr_on_close(int status, void *context)
{
    struct timeval attr_tmout = {10, 0};

    AFLOG_INFO("connmgr_attr_on_close:: IPC connection to ATTRD closed, status=%d", status);
    if (connmgr_evbase) {
        AFLOG_INFO("connmgr_attr_on_close:: schedule reconnection to ATTRD");
        event_base_once(connmgr_evbase, -1, EV_TIMEOUT, connmgr_reconn_to_attrd,
                        (void *)connmgr_evbase, &attr_tmout);
    }
}
