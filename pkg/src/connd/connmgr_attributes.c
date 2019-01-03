 /*F_ATTR_CONNMGR_ETH_IPADDR:
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>       /* time_t, struct tm, difftime, time, mktime */

#include "af_rpc.h"
#include "af_util.h"
#include "af_log.h"

#include "connmgr.h"
#include "connmgr_attributes.h"
#include "connmgr_stats.h"
#include "connmgr_util.h"

#include "build_info.h"

#define NET_CAPABILITY_FILE  "/usr/lib/af-conn/net_capabilities"


// Macros
//
#define INPUT_FILE_DETAIL(root,x) root #x

#define IS_OPERSTATE_UP(ops)                    \
    (strncasecmp(ops, "up", 2) == 0) ? 1 : 0    \

#define IS_OPERSTATE_DOWN(ops)                  \
    (strncasecmp(ops, "down", 4) == 0) ? 1 : 0  \

#define IS_OPERSTATE_DORMANT(ops)                  \
    (strncasecmp(ops, "dormant", 7) == 0) ? 1 : 0  \

// the MAC address length
#ifndef MAC_ADDR_LEN
    #define MAC_ADDR_LEN    6
#endif


extern struct event_base  *connmgr_evbase;

extern uint32_t connmgr_conn_to_attrd(struct event_base *ev_base);
extern void connmgr_shutdown();

#define SYSFS_HW_ADDR_PATH  "/sys/class/net/%s/address"
static int8_t  get_hwaddr(const char *dev, uint8_t *hw, size_t n)
{
	char     buf[64];
	char     fname[80];
	uint32_t bytes[6], i;

	if ((dev == NULL) || (n < MAC_ADDR_LEN)) {
		AFLOG_ERR("af_util_get_hwaddr:: invalid input");
		return (-1);
	}

	memset(bytes, 0, sizeof(bytes));
	memset(fname, 0, sizeof(fname));
	sprintf(fname, SYSFS_HW_ADDR_PATH, dev);
	if (af_util_read_file(fname, &buf[0], sizeof(buf)) > 0) {
		sscanf(buf, "%x:%x:%x:%x:%x:%x",
			   &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]);

		/* convert to uint8_t */
		for( i = 0; i < 6; ++i )
			hw[i] = (uint8_t) bytes[i];

		//af_log_buffer(LOG_DEBUG1, "READ_BUF", &buf[0], sizeof(buf));
		//af_log_buffer(LOG_DEBUG1, "HW_ADDRD", hw, 6);

		return (0);
	}
	return (-1);
}


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
	if ((conn_cb->flags & CM_MON_FLAGS_CONN_ACTIVE) == 0) {
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


/* cm_get_itfstate_itf
 *
 * return the connection control block based on the interface attribute
 */
static cm_conn_monitor_cb_t *cm_get_itf_conn_cb(uint32_t attributeId)
{
    cm_conn_monitor_cb_t *conn_cb_p = NULL;

    // which interface?
    if (attributeId == AF_ATTR_CONNMGR_ETH_ITF_STATE) {
        conn_cb_p = eth_mon_p;
    } else if (attributeId == AF_ATTR_CONNMGR_WIFI_ITF_STATE) {
        conn_cb_p = wlan_mon_p;
    } else if (attributeId == AF_ATTR_CONNMGR_WAN_ITF_STATE) {
        conn_cb_p = wan_mon_p;
    }

    return conn_cb_p;
}


static uint8_t cm_get_itf_state(cm_conn_monitor_cb_t *conn_cb_p)
{
    /* return value: (see device attribute registry)
     * 0 - Not Available/Broken
     * 1 - Up with no internet connectivity
     * 2 - Up with connection to Afero Cloud
     */
    if (conn_cb_p) {
        // interface is up and service is reachable
        if (conn_cb_p->dev_link_status == NETCONN_STATUS_ITFUP_SS) {
            return (2);
        }

        // interface is up, but service is not checked or failed checking
        if ((conn_cb_p->dev_link_status == NETCONN_STATUS_ITFUP_SU) ||
            (conn_cb_p->dev_link_status == NETCONN_STATUS_ITFUP_SF) ) {
           return (1);
        }
    }

    // reaches here means that the interface is not available
    return (0);
}


/* set the steady state and also send out a set to the other daemons know.
 */
void cm_attr_set_itf_state (cm_conn_monitor_cb_t  *conn_cb_p)
{
    int8_t   itf_state = cm_get_itf_state(conn_cb_p);
    int32_t  attributeId;
    int32_t  rc;
    uint8_t  set_attr = 1;
    static int8_t   last_wan_itf_state = -1;
    static int8_t   last_eth_itf_state = -1;
    static int8_t   last_wifi_itf_state= -1;

	if (conn_cb_p == NULL) {
        return;
    }

	if (conn_cb_p->my_idx == CM_MONITORED_WAN_IDX) {
		attributeId = AF_ATTR_CONNMGR_WAN_ITF_STATE;
        if (last_wan_itf_state == itf_state) {
            set_attr = 0;
        }
        last_wan_itf_state = itf_state;
    }
	else if (conn_cb_p->my_idx == CM_MONITORED_WLAN_IDX) {
		attributeId = AF_ATTR_CONNMGR_WIFI_ITF_STATE;
        if (last_wifi_itf_state == itf_state) {
            set_attr = 0;
        }
        last_wifi_itf_state = itf_state;
    }
    else if (conn_cb_p->my_idx == CM_MONITORED_ETH_IDX) {
        attributeId = AF_ATTR_CONNMGR_ETH_ITF_STATE;
        if (last_eth_itf_state == itf_state) {
            set_attr = 0;
        }
        last_eth_itf_state = itf_state;
    }
    else {
        // Not one of the interfaces, do nothing
        return;
    }

    if (set_attr) {
        AFLOG_DEBUG1("cm_attr_set_itf_state:: attrId=%d, state=%d", attributeId, itf_state);
        rc = af_attr_set(attributeId, (uint8_t *)&itf_state, sizeof(int8_t),
                        connmgr_attr_on_set_finished, NULL);
        if (rc != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("cm_attr_set_itf_state:: set failed for (itf_state=%d)", attributeId);
        }
    }

    return;
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
void connmgr_attr_on_owner_set(uint32_t attributeId, uint16_t setId, uint8_t *value, int length, void *context)
{
    int status = AF_ATTR_STATUS_OK;

	if (value == NULL) {
		AFLOG_ERR("connmgr_attr_on_owner_set:: invalid value=%p", value);
		return;
	}


	AFLOG_DEBUG2("connmgr_attr_on_owner_set:: attributeId=%d value=%s", attributeId, (char *) value);

	switch (attributeId) {
		case AF_ATTR_CONNMGR_DEBUG_LEVEL: {
			int8_t level = *(int8_t *)value;
			if (level < LOG_DEBUG_OFF) {
				level = LOG_DEBUG_OFF;
			}
			g_debugLevel = level;
			AFLOG_INFO("connmgr_attr_on_owner_set:: debug_level=%d", level);
			break;
		}

		default:
			AFLOG_ERR("connmgr_attr_on_owner_set:: unhandled attributeId=%d", attributeId);
            status = AF_ATTR_STATUS_NOT_IMPLEMENTED;
			break;

	} // switch

	int sendStatus = af_attr_send_set_response(status, setId);
	if (sendStatus != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("connmgr_attr_on_owner_set_send:sendStatus=%d,status=%d,setId=%d", sendStatus, status, setId);
	}
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
	int8_t			value = 0;
	char            buf[64];


	AFLOG_INFO("connmgr_attr_on_get_request:: get request for attribute=%d", attributeId);

	memset (buf, 0, sizeof(buf));
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

		case AF_ATTR_CONNMGR_REVISION:
			af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)REVISION, sizeof(REVISION));
			break;

		case AF_ATTR_CONNMGR_ETH_ITF_STATE:
		case AF_ATTR_CONNMGR_WIFI_ITF_STATE:
		case AF_ATTR_CONNMGR_WAN_ITF_STATE:
           {
				/* 0 - Not Available/Broken
                 * 1 - Up with no internet connectivity
                 * 2 - Up with connection to Afero Cloud
				 */
                value = cm_get_itf_state( cm_get_itf_conn_cb(attributeId) );
				AFLOG_INFO("connmgr_attr_on_get_request:: interface state=0x%02x", value);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(int8_t));
            }
			break;

		case AF_ATTR_CONNMGR_NET_CAPABILITIES: {
				if (af_util_file_exists(NET_CAPABILITY_FILE) == 1) {
					int rc;
					rc = af_util_system(NET_CAPABILITY_FILE);
					if (rc >= 0) {
						value = (uint8_t) rc;
					}
				}
				else {
					AFLOG_ERR("connmgr_attr_on_get_request:: no NET CAPABILITY file");
				}

				AFLOG_INFO("NET_CAPABILITIES=0x%02x", value);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(int8_t));
			}
			break;

		case AF_ATTR_CONNMGR_WIFI_UPTIME:
		case AF_ATTR_CONNMGR_ETH_UPTIME:
		case AF_ATTR_CONNMGR_WAN_UPTIME: {
				cm_conn_monitor_cb_t *tmp_p = wlan_mon_p;
				time_t    end_time;
				double    diff = 0;
				uint32_t  uptime = 0;
				uint8_t buf[sizeof(uptime)];

				if (attributeId == AF_ATTR_CONNMGR_ETH_UPTIME) {
					tmp_p = eth_mon_p;
				} else if (attributeId == AF_ATTR_CONNMGR_WAN_UPTIME) {
					tmp_p = wan_mon_p;
				}

				if ((tmp_p) && (tmp_p->flags & CM_MON_FLAGS_CONN_ACTIVE)) {
					time(&end_time);
					diff = difftime(end_time, tmp_p->start_uptime);
				}
				uptime = (uint32_t) diff;

				af_attr_store_uint32(buf, uptime);
				AFLOG_INFO("connmgr_attr_on_get_request:: %s  uptime=%d", ((tmp_p==NULL) ? "--":tmp_p->dev_name), uptime);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, buf, sizeof(buf));
			}
			break;

		case AF_ATTR_CONNMGR_WIFI_MAC_ADDR:
		case AF_ATTR_CONNMGR_ETH_MAC_ADDR: {
				uint8_t  mac[MAC_ADDR_LEN];
				memset(&mac[0], 0, sizeof(mac));
				if (attributeId == AF_ATTR_CONNMGR_WIFI_MAC_ADDR) {
					get_hwaddr(NETIF_NAME(WIFISTA_INTERFACE_0), &mac[0], sizeof(mac));
				}
				if (attributeId == AF_ATTR_CONNMGR_ETH_MAC_ADDR) {
					get_hwaddr(NETIF_NAME(ETH_INTERFACE_0), &mac[0], sizeof(mac));
				}
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&mac[0], sizeof(mac));
			}
			break;

		case AF_ATTR_CONNMGR_WIFI_IPADDR:
		case AF_ATTR_CONNMGR_WAN_IPADDR:
		case AF_ATTR_CONNMGR_ETH_IPADDR: {
				struct in_addr  addr;

				memset(&addr, 0, sizeof(addr));
				if (attributeId == AF_ATTR_CONNMGR_ETH_IPADDR) {
					get_itf_ipaddr(eth_mon_p->dev_name, AF_INET, buf, INET_ADDRSTRLEN+1);
				}
				else if (attributeId == AF_ATTR_CONNMGR_WIFI_IPADDR) {
					get_itf_ipaddr(wlan_mon_p->dev_name, AF_INET, buf, INET_ADDRSTRLEN+1);
				}
				else { // wan connection
					get_itf_ipaddr(wan_mon_p->dev_name, AF_INET, buf, INET_ADDRSTRLEN+1);
				}
				inet_aton(buf, &addr);

				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&(addr.s_addr), sizeof(uint32_t));
			}
			break;


		case AF_ATTR_CONNMGR_WIFI_UL_DATA_USAGE:    // transmit bytes
		case AF_ATTR_CONNMGR_WIFI_DL_DATA_USAGE: {  // receive bytes
				uint32_t   stats = 0;
				uint8_t    data[sizeof(stats)];
				cm_stats_t *tmp_p = connmgr_get_data_usage_cb(CM_MONITORED_WLAN_IDX);
				if (tmp_p) {
					stats = ((attributeId == AF_ATTR_CONNMGR_WIFI_UL_DATA_USAGE) ?
								tmp_p->traffic_stats.tx_bytes  : tmp_p->traffic_stats.rx_bytes);
				}
				af_attr_store_uint32(data, stats);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, data, sizeof(uint32_t));
			}
			break;

		case AF_ATTR_CONNMGR_WAN_UL_DATA_USAGE:
		case AF_ATTR_CONNMGR_WAN_DL_DATA_USAGE: {
				uint32_t   stats = 0;
				uint8_t    data[sizeof(stats)];
				cm_stats_t *tmp_p = connmgr_get_data_usage_cb(CM_MONITORED_WAN_IDX);
				if (tmp_p) {
					stats = ((attributeId == AF_ATTR_CONNMGR_WAN_UL_DATA_USAGE) ?
								tmp_p->traffic_stats.tx_bytes  : tmp_p->traffic_stats.rx_bytes);
				}
				af_attr_store_uint32(data, stats);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, data, sizeof(stats));
			}
			break;

		case AF_ATTR_CONNMGR_ETH_DL_DATA_USAGE:
		case AF_ATTR_CONNMGR_ETH_UL_DATA_USAGE: {
				uint32_t   stats = 0;
				uint8_t    data[sizeof(stats)];
				cm_stats_t *tmp_p = connmgr_get_data_usage_cb(CM_MONITORED_ETH_IDX);
				if (tmp_p) {
					stats = ((attributeId == AF_ATTR_CONNMGR_ETH_UL_DATA_USAGE) ?
								tmp_p->traffic_stats.tx_bytes : tmp_p->traffic_stats.rx_bytes);
				}
				af_attr_store_uint32(data, stats);
				af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, data, sizeof(stats));
			}
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
		exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
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

