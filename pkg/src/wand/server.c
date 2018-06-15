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
#include <event2/event.h>
#include "af_log.h"
#include "server.h"
#include "af_attr_client.h"
#include "ril.h"
#include "build_info.h"
#include "../include/signal_tracker.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static void wan_attr_on_close(int status, void *context);

/* Flag to indicate if we should periodically send signal strengh info */
static uint8_t sReportRssi = 0;
static struct event *sTimerEvent = NULL;

#define RSCP_REPORTING_INTERVAL_SECONDS 5
#define NUM_RSRP_TO_AVERAGE 8
#define RSRP_DIFF_TO_REPORT 3

typedef enum {
    BIT_RATE_STATE_NONE = 0,
    BIT_RATE_STATE_FETCHING_USAGE,
    BIT_RATE_STATE_FETCHING_UPTIME
} bit_rate_state_t;

struct bit_rate_struct {
    int32_t usage;
    uint16_t getId;
    bit_rate_state_t state;
};

static struct bit_rate_struct sDLBitRateStruct = { .usage = 0, .state = BIT_RATE_STATE_NONE };
static struct bit_rate_struct sULBitRateStruct = { .usage = 0, .state = BIT_RATE_STATE_NONE };


static void on_report_rssi_timer(evutil_socket_t fd, short what, void *arg)
{
    uint8_t bars;
    int16_t rsrp;

    ril_wan_status_t *wStatus = ril_lock_wan_status();
    bars = wStatus->bars;
    rsrp = wStatus->rsrp;
    ril_unlock_wan_status();

    int rc = af_attr_set(AF_ATTR_WAN_WAN_BARS, &bars, sizeof(uint8_t), NULL, NULL);
    if (rc != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("wifistad_report_rssi_info:rc=%d:set failed", rc);
    }

    rsrp = sigtrack_add(rsrp, RSRP_DIFF_TO_REPORT);
    if (rsrp) {
        uint8_t rsrpLE[2];
        af_attr_store_uint16(rsrpLE, rsrp); /* rsrp will be less than 32768 */
        rc = af_attr_set(AF_ATTR_WAN_WAN_RSRP, rsrpLE, sizeof(rsrpLE), NULL, NULL);
        if (rc != AF_ATTR_STATUS_OK) {
            AFLOG_WARNING("wifistad_report_rssi_info:rc=%d:set failed", rc);
        }
    }

    struct timeval tv = { RSCP_REPORTING_INTERVAL_SECONDS, 0 };
    evtimer_add(sTimerEvent, &tv);
}

static void set_up_rssi_reporting(int on)
{
    uint8_t newValue = (on != 0);
    if (newValue != sReportRssi) {
        sReportRssi = newValue;
        AFLOG_INFO("set_up_rssi_reporting:reportRssi=%d", sReportRssi);
        if (sReportRssi) {
            sigtrack_clear(NUM_RSRP_TO_AVERAGE);
            sTimerEvent = evtimer_new(wand_get_evbase(), on_report_rssi_timer, NULL);
            if (sTimerEvent == NULL) {
                AFLOG_ERR("set_up_rssi_reporting_timer:errno=%d", errno);
                return;
            }
            struct timeval tv = { RSCP_REPORTING_INTERVAL_SECONDS, 0 };
            evtimer_add(sTimerEvent, &tv);
        } else {
            evtimer_del(sTimerEvent);
            event_free(sTimerEvent);
        }
    }
}

// on notification
static void wan_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{

    if (value == NULL) {
        AFLOG_ERR("wan_attr_on_notify:: invalid input=%p", value);
        return;
    }

    AFLOG_DEBUG2("wan_attr_on_notify:: attributeId=%d value=%s", attributeId, (char *)value);
    switch (attributeId) {
        case AF_ATTR_ATTRD_REPORT_RSSI_CHANGES:
            set_up_rssi_reporting(value[0]);
            break;

        default:
            AFLOG_WARNING("wan_attr_on_notify:: unhandled attribute=%d", attributeId);
            break;
    }
}

static void on_uptime_get(uint8_t status, uint32_t attrId, uint8_t *value, int length, void *context)
{
    if (context != NULL) {
        struct bit_rate_struct *br = (struct bit_rate_struct *)context;
        if (status == AF_ATTR_STATUS_OK) {
            if (length == sizeof(int32_t)) {
                int32_t uptime = af_attr_get_int32(value);
                int32_t bitrate = (uptime != 0 ? (br->usage / uptime) * 8 : 0);
                AFLOG_DEBUG1("usage=%d,uptime=%d,bitrate=%d", br->usage, uptime, bitrate);
                uint8_t buf[sizeof(int32_t)];
                af_attr_store_int32(buf, bitrate);
                int sendStatus = af_attr_send_get_response(status, br->getId, buf, sizeof(buf));
                if (sendStatus != AF_ATTR_STATUS_OK) {
                    AFLOG_WARNING("on_uptime_get_send:status=%d", sendStatus);
                }
                br->state = BIT_RATE_STATE_NONE;
            } else {
                AFLOG_WARNING("on_uptime_get_length:length=%d", length);
                af_attr_send_get_response(AF_ATTR_STATUS_BAD_DATA, br->getId, NULL, 0);
                br->state = BIT_RATE_STATE_NONE;
            }
        } else {
            AFLOG_WARNING("on_uptime_get_status:status=%d", status);
            af_attr_send_get_response(status, br->getId, NULL, 0);
            br->state = BIT_RATE_STATE_NONE;
        }
    }
}

static void on_usage_get(uint8_t status, uint32_t attrId, uint8_t *value, int length, void *context)
{
    if (context != NULL) {
        struct bit_rate_struct *br = (struct bit_rate_struct *)context;
        if (status == AF_ATTR_STATUS_OK) {
            if (length == sizeof(int32_t)) {
                br->usage = af_attr_get_int32(value);
                AFLOG_DEBUG1("Data usage is %d", br->usage);
                int getStatus = af_attr_get(AF_ATTR_CONNMGR_WAN_UPTIME, on_uptime_get, br);
                if (getStatus != AF_ATTR_STATUS_OK) {
                    AFLOG_WARNING("on_usage_get_get:status=%d", getStatus);
                    af_attr_send_get_response(getStatus, br->getId, NULL, 0);
                    br->state = BIT_RATE_STATE_NONE;
                } else {
                    br->state = BIT_RATE_STATE_FETCHING_UPTIME;
                }
            } else {
                AFLOG_WARNING("on_usage_get_length:length=%d", length);
                af_attr_send_get_response(AF_ATTR_STATUS_BAD_DATA, br->getId, NULL, 0);
                br->state = BIT_RATE_STATE_NONE;
            }
        } else {
            AFLOG_WARNING("on_usage_get_status:status=%d", status);
            af_attr_send_get_response(status, br->getId, NULL, 0);
            br->state = BIT_RATE_STATE_NONE;
        }
    }
}

static void wan_get_request(uint32_t attrId, uint16_t getId, void *context)
{
    uint8_t buf[4];

    ril_wan_status_t *wStatus = ril_lock_wan_status();
    switch (attrId) {
        case AF_ATTR_WAN_WAN_BARS :
            af_attr_send_get_response(0, getId, &(wStatus->bars), sizeof(wStatus->bars));
            break;
        case AF_ATTR_WAN_WAN_RSRP :
            af_attr_store_int16(buf, wStatus->rsrp);
            af_attr_send_get_response(0, getId, buf, sizeof(wStatus->rsrp));
            break;
        case AF_ATTR_WAN_WAN_ITF_STATE :
            buf[0] = wan_interface_state();
            af_attr_send_get_response(0, getId, buf, sizeof(int8_t));
            break;
        case AF_ATTR_WAN_WAN_IMEISV :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->imeisv, strlen(wStatus->imeisv) + 1);
            break;
        case AF_ATTR_WAN_WAN_IMSI :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->imsi, strlen(wStatus->imsi) + 1);
            break;
        case AF_ATTR_WAN_WAN_ICCID :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->iccid, strlen(wStatus->iccid) + 1);
            break;
        case AF_ATTR_WAN_WAN_RAT :
            af_attr_send_get_response(0, getId, &wStatus->rat, sizeof(wStatus->rat));
            break;
        case AF_ATTR_WAN_WAN_REG_STATE :
            af_attr_send_get_response(0, getId, &wStatus->regState, sizeof(wStatus->regState));
            break;
        case AF_ATTR_WAN_WAN_PS_STATE :
            af_attr_send_get_response(0, getId, &wStatus->psState, sizeof(wStatus->psState));
            break;
        case AF_ATTR_WAN_WAN_ROAMING_STATE :
            af_attr_send_get_response(0, getId, &wStatus->roamingState, sizeof(wStatus->roamingState));
            break;
        case AF_ATTR_WAN_WAN_SIM_STATUS :
            af_attr_send_get_response(0, getId, &wStatus->simStatus, sizeof(wStatus->simStatus));
            break;
        case AF_ATTR_WAN_WAN_MCC :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->mcc, sizeof(wStatus->mcc));
            break;
        case AF_ATTR_WAN_WAN_MNC :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->mnc, sizeof(wStatus->mnc));
            break;
        case AF_ATTR_WAN_WAN_LAC :
            af_attr_store_uint32(buf, wStatus->lac);
            af_attr_send_get_response(0, getId, buf, sizeof(wStatus->lac));
            break;
        case AF_ATTR_WAN_WAN_CELL_ID :
            af_attr_store_uint16(buf, wStatus->pcid);
            af_attr_send_get_response(0, getId, buf, sizeof(wStatus->pcid));
            break;
        case AF_ATTR_WAN_WAN_PLMN :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->plmn, strlen(wStatus->plmn) + 1);
            break;
        case AF_ATTR_WAN_WAN_APN :
        {
            char tmpApn[PDN_APN_LEN_MAX + 1];
            strncpy(tmpApn, wan_apn(), sizeof(tmpApn));
            tmpApn[PDN_APN_LEN_MAX] = '\0';
            af_attr_send_get_response(0, getId, (uint8_t *)tmpApn, strlen(tmpApn) + 1);
            break;
        }
        case AF_ATTR_WAN_DEBUG_LEVEL:
        {
            uint8_t value = g_debugLevel;
            AFLOG_INFO("wan_get_request: debug_level=%d", value);
            af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)&value, sizeof(uint8_t));
            break;
        }
        case AF_ATTR_WAN_NEIGHBOR_INFO :
            af_attr_send_get_response(0, getId, (uint8_t *)wStatus->neighborInfo, strlen(wStatus->neighborInfo) + 1);
            break;

        case AF_ATTR_WAN_WAN_DL_BIT_RATE :
            if (sDLBitRateStruct.state == BIT_RATE_STATE_NONE) {
                sDLBitRateStruct.getId = getId;
                int status = af_attr_get(AF_ATTR_CONNMGR_WAN_DL_DATA_USAGE, on_usage_get, &sDLBitRateStruct);
                if (status == AF_ATTR_STATUS_OK) {
                    sDLBitRateStruct.state = BIT_RATE_STATE_FETCHING_USAGE;
                }
            }
            break;
        case AF_ATTR_WAN_WAN_UL_BIT_RATE :
            if (sULBitRateStruct.state == BIT_RATE_STATE_NONE) {
                sULBitRateStruct.getId = getId;
                int status = af_attr_get(AF_ATTR_CONNMGR_WAN_UL_DATA_USAGE, on_usage_get, &sULBitRateStruct);
                if (status == AF_ATTR_STATUS_OK) {
                    sULBitRateStruct.state = BIT_RATE_STATE_FETCHING_USAGE;
                }
            }
            break;
        case AF_ATTR_WAN_REVISION:
            af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)REVISION, sizeof(REVISION));
            break;

        default :
            AFLOG_WARNING("get_attribute_not_found:attr=%d", attrId);
            break;
    }
    ril_unlock_wan_status();
}

static void wan_attr_on_owner_set(uint32_t attributeId, uint16_t setId, uint8_t *value, int length, void *context)
{
    int status = AF_ATTR_STATUS_OK;

    if (value == NULL) {
        AFLOG_ERR("wan_attr_on_owner_set_value:value_NULL=%d", value == NULL);
        return;
    }

    switch (attributeId) {
        case AF_ATTR_WAN_DEBUG_LEVEL: {
            int8_t level = *(int8_t *)value;
            if (level < LOG_DEBUG_OFF) {
                level = LOG_DEBUG_OFF;
            }
            g_debugLevel = level;
            AFLOG_INFO("wan_attr_on_owner_set_debug:debug_level=%d", level);
            break;
        }

        default:
            AFLOG_ERR("wan_attr_on_owner_set_unknown:attributeId=%d", attributeId);
            status = AF_ATTR_STATUS_NOT_IMPLEMENTED;
            break;

    } // switch

    int sendStatus = af_attr_send_set_response(status, setId);
    if (sendStatus != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("wan_attr_on_owner_set_send:sendStatus=%d,status=%d,setId=%d", sendStatus, status, setId);
    }
}

int wan_ipc_init(struct event_base *base)
{
    if (base == NULL) {
        AFLOG_ERR("wan_ipc_init::base==NULL");
        return -1;
    }

    af_attr_range_t ranges[] = {
        {AF_ATTR_ATTRD_REPORT_RSSI_CHANGES, AF_ATTR_ATTRD_REPORT_RSSI_CHANGES}
    };

    int err = af_attr_open(base, "IPC.WAN",
                           ARRAY_SIZE(ranges), ranges,
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
static void wan_reconn_to_attrd(evutil_socket_t fd, short events, void *arg)
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
        AFLOG_ERR("wan_reconn_to_attrd:base==NULL:event_base is incorrect; exit");

        wand_shutdown();
        exit(1);
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
static void wan_attr_on_close(int status, void *context)
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
