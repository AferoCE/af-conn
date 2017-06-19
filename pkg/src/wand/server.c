/*
 * server.c -- WAND server implementation
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Clif Liu and Tina Cheung
 */

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <event.h>
#include <stdlib.h>
#include "af_log.h"
#include "server.h"
#include "af_attr_client.h"
#include "ril.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

extern void wand_shutdown(void);
extern struct event_base *wand_get_evbase();
extern void wan_attr_on_close(int status, void *context);

// express interested to attribute daemon that we are interested in the
// notification for the following attributes.
af_attr_range_t  g_wand_attr_ranges[1] = {
        {AF_ATTR_ATTRD_REPORT_RSSI_CHANGES, AF_ATTR_ATTRD_REPORT_RSSI_CHANGES},
};
#define NUM_WAND_ATTR_RANGES  ARRAY_SIZE(g_wand_attr_ranges)
#define FIXED_RSRP (-999)
static uint8_t sRsrp[] = { (65536 + FIXED_RSRP) & 0xff, (65536 + FIXED_RSRP) >> 8 };

/* Flag to indicate if we should periodically send signal strengh info*/
uint8_t  periodic_rpt_rssi = 0;


/* wan_rpt_rssi_info
 *
 * report signal strengh info
 */
void wan_rpt_rssi_info()
{
    int rc;

    uint8_t bars = ril_get_bars();
    rc = af_attr_set(AF_ATTR_WAN_BARS, (uint8_t *)&bars, sizeof(uint8_t),
                     NULL, NULL);
    if (rc != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("wifistad_report_rssi_info:rc=%d:set failed", rc);
    }

    rc = af_attr_set(AF_ATTR_WAN_RSRP, sRsrp, sizeof(sRsrp), NULL, NULL);
    if (rc != AF_ATTR_STATUS_OK) {
        AFLOG_WARNING("wifistad_report_rssi_info:rc=%d:set failed", rc);
    }

    return;
}


// on notification
void wan_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{

    if (value == NULL) {
        AFLOG_ERR("wan_attr_on_notify:: invalid input=%p", value);
        return;
    }

    AFLOG_DEBUG2("wan_attr_on_notify:: attributeId=%d value=%s", attributeId, (char *)value);
    switch (attributeId) {
        case AF_ATTR_ATTRD_REPORT_RSSI_CHANGES:
            {
                uint8_t  report_rssi_change = *value;

                if (report_rssi_change == 1) {  // activate periodic rssi reporting
                    periodic_rpt_rssi = 1;
                }
                else {  // deactivate periodic rssi reporting
                    periodic_rpt_rssi = 0;
                }
            }
            break;


        default:
            AFLOG_WARNING("wan_attr_on_notify:: unhandled attribute=%d", attributeId);
            break;
    }
    return;
}


void wan_get_request(uint32_t attrId, uint16_t getId, void *context)
{
    char *s;

    switch (attrId) {
        case AF_ATTR_WAN_BARS :
        {
            uint8_t bars = ril_get_bars();
            af_attr_send_get_response(0, getId, &bars, sizeof(bars));
            break;
        }
        case AF_ATTR_WAN_RSRP :
            af_attr_send_get_response(0, getId, sRsrp, sizeof(sRsrp));
            break;
        case AF_ATTR_WAN_POWER_INFO :
            s = ril_get_sim_status();
            af_attr_send_get_response(s ? 0 : AF_ATTR_STATUS_UNSPECIFIED, getId, (uint8_t *)s, (s ? strlen(s) + 1 : 0));
            break;
        case AF_ATTR_WAN_CAMP_INFO :
            s = ril_get_camp_status();
            af_attr_send_get_response(s ? 0 : AF_ATTR_STATUS_UNSPECIFIED, getId, (uint8_t *)s, (s ? strlen(s) + 1 : 0));
            break;
        case AF_ATTR_WAN_SERVING_INFO :
            s = ril_get_serving_status();
            af_attr_send_get_response(s ? 0 : AF_ATTR_STATUS_UNSPECIFIED, getId, (uint8_t *)s, (s ? strlen(s) + 1 : 0));
            break;
        case AF_ATTR_WAN_NEIGHBOR_INFO :
            s = ril_get_neighbor_status();
            af_attr_send_get_response(s ? 0 : AF_ATTR_STATUS_UNSPECIFIED, getId, (uint8_t *)s, (s ? strlen(s) + 1 : 0));
            break;
        case AF_ATTR_WAN_AVAILABLE :
        {
            uint8_t exists = wan_exists();
            af_attr_send_get_response(0, getId, &exists, sizeof(exists));
            break;
        }

        case AF_ATTR_WAN_DEBUG_LEVEL:
        {
            uint8_t value = g_debugLevel;
            AFLOG_INFO("wan_get_request: debug_level=%d", value);
            af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(uint8_t));
            break;
        }

        default :
            break;
    }
}

void notify_wan_existence(void)
{
    uint8_t exists = wan_exists();
    af_attr_set(AF_ATTR_WAN_AVAILABLE, &exists, sizeof(exists), NULL, NULL);
}


int wan_attr_on_owner_set(uint32_t attributeId, uint8_t *value, int length, void *context)
{
    int status = AF_ATTR_STATUS_OK;

    if (value == NULL) {
        AFLOG_ERR("wan_attr_on_owner_set:: invalid value=%p", value);
        return AF_ATTR_STATUS_UNSPECIFIED;
    }

    switch (attributeId) {
        case AF_ATTR_WAN_DEBUG_LEVEL: {
            int8_t level = *(int8_t *)value;
            if (level < LOG_DEBUG_OFF) {
                level = LOG_DEBUG_OFF;
            }
            g_debugLevel = level;
            AFLOG_INFO("wan_attr_on_owner_set:i debug_level=%d", level);
            break;
        }

        default:
            AFLOG_ERR("wan_attr_on_owner_set:: unhandled attributeId=%d", attributeId);
            status = AF_ATTR_STATUS_NOT_IMPLEMENTED;
            break;

    } // switch

    return status;
}


int wan_ipc_init(struct event_base *base)
{
    if (base == NULL) {
        AFLOG_ERR("wan_ipc_init::base==NULL");
        return -1;
    }

    int err = af_attr_open(base, "IPC.WAN",
                           NUM_WAND_ATTR_RANGES, &g_wand_attr_ranges[0],
                           wan_attr_on_notify,    // on_notify
                           wan_attr_on_owner_set, // on_set
                           wan_get_request,       // on_get
                           wan_attr_on_close,     // on_close
                           NULL,                  // on_open
                           NULL);                 // context
    if (err != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("wan_ipc_init_open:err=%d", err);
        return -1;
    }

    return 0;
}

void wan_ipc_shutdown(void)
{
    af_attr_close();
}


/* wan_reconn_to_attrd
 *  - attempt to reconnect to attrd after a waiting period.  The waiting
 *    is 10 sec
 */
void wan_reconn_to_attrd(evutil_socket_t fd, short events, void *arg)
{
    int rc = -1;
    struct event_base *base = (struct event_base *)arg;

    if (base) {
        AFLOG_INFO("wan_reconn_to_attrd:: reconnecting");
        rc = wan_ipc_init(base);
        if (rc < 0) {
            wan_attr_on_close(AF_ATTR_STATUS_OK, NULL);
        }
    }
    else {
        AFLOG_ERR("wan_reconn_to_attrd:: event_base went bonkers.exit");

        wan_ipc_shutdown();
        wand_shutdown();
        exit(-1);
    }
}


// wan_attr_on_close
//
// When the attrd daemon closed, freed as a client, closed its connection too.
// However, the freed needs to connect to attrd in order to work properly
// with its attributes.
//
// Try to reconnect to it after a period of time.
//
void wan_attr_on_close(int status, void *context)
{
    struct timeval attr_tmout = {10, 0};
    struct event_base *evbase = wand_get_evbase();

    AFLOG_INFO("wan_attr_on_close:: IPC connection to ATTRD closed, status=%d", status);
    if (evbase) {
        AFLOG_INFO("wan_attr_on_close:: schedule reconnection to ATTRD");
        event_base_once(evbase, -1, EV_TIMEOUT, wan_reconn_to_attrd,
                        (void *)evbase, &attr_tmout);
    }
}
