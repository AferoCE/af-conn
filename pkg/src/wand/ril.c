/*
 * ril.c -- Radio Interface Layer implementation
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Kai Hu, Clif Liu, and Evan Jeng
 *
 * LTE only
 */
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <event2/event.h>

#include "af_log.h"
#include "at.h"
#include "ril.h"

/******************************************************************************/
/* AT command enums */
/* Network selection options */

/* PS STATUS REPORTING*/
typedef enum {
    AT_OPT_PS_REPORT_DISABLE = 0,
    AT_OPT_PS_REPORT_ENABLE,      /* state change report */
    AT_OPT_PS_REPORT_ENABLE_ALL  /* all report: state + cell */
} at_opt_ps_unsol_t;

typedef enum {
    AT_OPT_ERROR_DISABLE,
    AT_OPT_ERROR_NUMERIC,
    AT_OPT_ERROR_VERBOSE
} at_opt_error_report_t;

typedef enum {
    AT_OPT_PS_EVENT_BUFFER = 0,
    AT_OPT_PS_EVENT_REPORT,
    AT_OPT_PS_EVENT_REPORT_WITH_HISTORY,
    AT_OPT_PS_EVENT_MODE_MAX
} at_opt_ps_event_report_t;

/******************************************************************************/


#define AT_ROUTE_CID_PATH "/USBCDC/"
#define AT_ROUTE_TID_PATH "/USBHS/NCM/"


#define AT_CID_MAX 20

typedef enum {
    /* first four profiles are reserved */
    APN_PROFILE_RESERVED_1 = 0,
    APN_PROFILE_DEFAULT = APN_PROFILE_RESERVED_1,
    APN_PROFILE_RESERVED_2,
    APN_PROFILE_RESERVED_3,
    APN_PROFILE_RESERVED_4,
    APN_PROFILE_RESERVED_5,
    APN_PROFILE_MAX
} apn_profile_idx;

typedef enum {
    DATA_CONNECTION_STATE_IDLE,
    DATA_CONNECTION_STATE_PENDING,
    DATA_CONNECTION_STATE_ACTIVE
} data_connection_state;

typedef enum {
    PDN_PROTOCOL_IP,
    PDN_PROTOCOL_IPV6,
    PDN_PROTOCOL_IPV4V6,
    PDN_PROTOCOL_INVALID
} pdn_protocol;

#define AT_CMD_UNLOCK_PROFILE          "+HBHV"
#define AT_CMD_SET_PHONE_FUNCTIONALITY "+CFUN"
#define AT_CMD_MANUFACTURER_ID         "+CGMI"
#define AT_CMD_ECHO                    "E"
#define AT_CMD_PS_EVENT_REPORT         "+CGEREP"
#define AT_CMD_PS_STATUS_LTE           "+CEREG"
#define AT_CMD_PDN_ACTIVATION          "+CGACT"
#define AT_CMD_DATA_CHANNEL_ROUTE      "+XDATACHANNEL"
#define AT_CMD_DNS_REQUEST             "+XDNS"
#define AT_CMD_IP_SETTING              "+CGPADDR"
#define AT_CMD_ENTER_DATA_STATE        "+CGDATA"
#define AT_CMD_PDN_PROFILE             "+CGDCONT"
#define AT_CMD_PDN_AUTH_SETTING        "+WPPP"
#define AT_CMD_SET_ERROR_REPORT        "+CMEE"
#define AT_CMD_NETWORK_SELECTION       "+COPS"
#define AT_CMD_PS_ATTACH               "+CGATT"
#define AT_CMD_SIGNAL_QUALITY          "+XCESQ"
#define AT_CMD_ICCID                   "+CCID"
#define AT_CMD_IMEISV                  "+KGSN"
#define AT_CMD_IMSI                    "+CIMI"
#define AT_CMD_CAMPED_CELL_INFO        "+KCCINFO"
#define AT_CMD_CELL_ENVIRONMENT_INFO   "+KCELL"

#define AT_UNSOL_PS_EVENT              "+CGEV"
#define AT_UNSOL_REGISTRATION_EVENT    "+CEREG"

typedef struct {
    int cid;
    int nid;
    int state;
    char ip_v4[INET_ADDRSTRLEN];
    char ip_v6[INET6_ADDRSTRLEN];
    char dns1_v4[INET_ADDRSTRLEN];
    char dns2_v4[INET_ADDRSTRLEN];
    char dns1_v6[INET6_ADDRSTRLEN];
    char dns2_v6[INET6_ADDRSTRLEN];
} data_connection_t;

typedef struct {
    const int  cid;
    int  valid;                                // cached profile is valid
    char auth_type[PDN_AUTH_TYPE_LEN_MAX + 1];
    char protocol[PDN_PROTOCOL_LEN_MAX + 1];   // IP, IPV6, IPV4V6
    char apn[PDN_APN_LEN_MAX + 1];
    char user[PDN_USER_LEN_MAX + 1];
    char password[PDN_PASSWORD_LEN_MAX + 1];
} apn_profile_t;

static apn_profile_t sProfiles[APN_PROFILE_MAX];
static data_connection_t sConnection;
static ril_event_callback_t sRilEventCallback = NULL;
static void *sRilEventContext;
static struct event_base *sEventBase;

static apn_profile_t * prv_prepare_apn_profile(ril_data_call_request_t *req);

static int sConnectionId = -1;

#define POWER_OFF_STATUS "PWR=0"

static char sIccid[32] = "";
static char sSimStatus[128] = POWER_OFF_STATUS;
static char sCampStatus[128] = "";
static char sServingStatus[128] = "";
static char sNeighborStatus[256] = "";
static int sBars = 0; // 0-5 0 == not camped

#define EV(_x) #_x

static char *s_event_names[] = {
    ALLEVENTS
};

static void prv_ril_send_event(ril_event_t event)
{
    AFLOG_DEBUG1("prv_ril_send_event %s", s_event_names[event]);
    if (sRilEventCallback) {
        (sRilEventCallback) (event, sRilEventContext);
    }
}


static void prv_on_ps_event(char *rest, void *context)
{
    char *token[5];
    int num_tokens;

    num_tokens = at_tokenize_line(rest, ' ', token, ARRAY_SIZE(token));

    /* TODO sConnection not protected! */
    if (num_tokens >= 4) {
        if (!strcmp(token[1],"PDN")) {
            if (!strcmp(token[2],"DEACT")) {
                int cid = atoi(token[3]);
                if (sConnection.cid == cid) {
                    sConnection.state = DATA_CONNECTION_STATE_IDLE;
                    prv_ril_send_event(RIL_EVENT_DATA_CALL_LOST);
                }
            }
        }
    }
}

static void prv_on_ps_status_lte(char *rest, void *context)
{
    AFLOG_DEBUG2("on_ps_status_lte rest=\"%s\"", rest);
}

void prv_on_registration_event(char *rest, void *context)
{
    AFLOG_DEBUG2("on_registration_event rest=\"%s\"", rest);
}

void prv_on_signal_quality(char *rest, void *context)
{
    AFLOG_DEBUG2("on_signal_quality rest=\"%s\"", rest);
}



static int prv_update_apn_profile(apn_profile_t *profile, char *apn, char *protocol)
{
    if (strlen(apn) >= sizeof(profile->apn))
        return -1;

    if (strlen(protocol) >= sizeof(profile->protocol))
        return -1;

    strncpy(profile->apn, apn, sizeof(profile->apn));
    strncpy(profile->protocol, protocol, sizeof(profile->protocol));
    profile->valid = 1;
    AFLOG_DEBUG3 ("profile apn=%s protocol=%s", profile->apn, profile->protocol);
    return 0;
}

static apn_profile_t *prv_get_apn_profile(int cid)
{
    int idx;
    idx = cid - 1;
    if (idx < 0 || idx >= APN_PROFILE_MAX)
        return NULL;
    return &sProfiles[idx];
}

static int prv_update_apn_profile_cache(void)
{
    char *line;
    /* Update PDN */
    if (at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_PDN_PROFILE, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("update_apn_profile_cache::failed to query pdn profile");
        return -1;
    }

    while ((line = at_rsp_next_line()) != NULL) {
        char *token[3], *protocol, *apn;
        int num_tokens, cid;
        apn_profile_t *profile;
        AFLOG_DEBUG3("prv_update_apn_profile_cache::line::%s", line);
        num_tokens = at_tokenize_line(line, ',', token, ARRAY_SIZE(token));

        if (num_tokens != ARRAY_SIZE(token))
            return -1;

        cid = strtol(token[0], NULL, 10);
        if (cid <= 0 || cid > AT_CID_MAX) {
            AFLOG_ERR("update_apn_cache::failed to parse cid::cid=%s", token[0]);
            continue;
        }

        protocol = token[1];
        apn = token[2];
        if (protocol == NULL || apn == NULL) {
            AFLOG_ERR("update_apn_cache::bad response::rsp=%s", line);
            continue;
        }
        profile = prv_get_apn_profile(cid);
        if (profile == NULL) {
            AFLOG_WARNING("update_apn_cache::invalid pdn profile::cid=%d", cid);
            continue;
        }

        if (prv_update_apn_profile(profile, apn, protocol) != 0) {
            AFLOG_ERR("update_apn_cache::failed to update profile");
            continue;
        }

        AFLOG_DEBUG2("update_apn_cache::cid=%d,apn=%s,ip=%s", cid, apn, protocol);
    }
    return 0;
}

#define SELECT_NETWORK_TIMEOUT 300 /* allow 300 seconds to select network */

int ril_select_network(ril_data_call_request_t *dataCallReq)
{
    int retVal = -1;

    AFLOG_DEBUG3("prepare_apn_profile:apn=%s protocol=%s", dataCallReq->apn, dataCallReq->protocol);

    at_start_cmds();

    apn_profile_t *profile = prv_prepare_apn_profile(dataCallReq);
    if (profile == NULL) {
        AFLOG_ERR("ril_select_network::failed to prepare apn profile");
        goto exit;
    }

    AFLOG_INFO("prv_select_network:timeout=%d", SELECT_NETWORK_TIMEOUT);
    int res = at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_NETWORK_SELECTION, "=0", SELECT_NETWORK_TIMEOUT);
    if (res != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("prv_select_network:res=%d:can't select network", res);
        goto exit;
    }

    retVal = 0;

exit:
    at_end_cmds();

    return retVal;
}

#define SNPRINTF(_buf,_space,_fmt,...) ((_space) > 1 ? snprintf((_buf), (_space), _fmt, ##__VA_ARGS__) : 0)
static int prv_modem_init(void)
{
    int pos = 0;
    int retVal = -1;

    sConnectionId = -1; /* unset the connection ID */

    at_start_cmds();

    /* Disable echo */
    if (at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_ECHO, "0", 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to configure echo");
        goto error;
    }
    /* Get the IMEI with SV */
    if (at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_IMEISV, "=2", 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to get IMEI");
        goto error;
    }
    char *token[2];
    int n = at_tokenize_line(at_rsp_next_line(), ' ', token, ARRAY_SIZE(token));
    if (n != ARRAY_SIZE(token)) {
        AFLOG_ERR("prv_modem_init::failed to parse IMEI+SV");
        return -1;
    }

    /* clear out the entire string so that we can never go off the end of the buffer */
    memset(sSimStatus, 0, sizeof(sSimStatus));

    pos += SNPRINTF(&sSimStatus[pos], sizeof(sSimStatus) - pos, "PWR=1 IMEI=%s SV=%s", token[0], &token[1][3]);

    /* Get the ICCID and detect the SIM */
    if (at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_ICCID, NULL, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::can't get iccid");
        goto error;
    }
    strncpy(sIccid, at_rsp_next_line(), sizeof(sIccid));
    sIccid[sizeof(sIccid) - 1] = '\0';
    pos += SNPRINTF(&sSimStatus[pos], sizeof(sSimStatus) - pos, " ICCID=%s", sIccid);

    /* Get the IMSI */
    if (at_send_cmd(AT_RSP_TYPE_NO_PREFIX, AT_CMD_IMSI, NULL, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::can't get imsi");
        goto error;
    }
    pos += SNPRINTF(&sSimStatus[pos], sizeof(sSimStatus) - pos, " IMSI=%s", at_rsp_next_line());

    /* Configure event reporting */
    if (at_send_cmd_1_int(AT_RSP_TYPE_OK, AT_CMD_SET_ERROR_REPORT, AT_OPT_ERROR_NUMERIC, 0)
            != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to configure error report");
        goto error;
    }

    if (at_send_cmd_1_int(AT_RSP_TYPE_OK, AT_CMD_PS_STATUS_LTE, AT_OPT_PS_REPORT_ENABLE_ALL, 0)
            != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to configure ps status reporting");
        goto error;
    }

    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_PS_EVENT_REPORT, AT_OPT_PS_EVENT_REPORT, 0, 0)
            != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to configure ps event reporting");
        goto error;
    }

    if (prv_update_apn_profile_cache() != 0) {
        AFLOG_ERR("prv_modem_init::failed to update apn profile cache");
        goto error;
    }

    retVal = 0;

error:
    at_end_cmds();

    return retVal;
}

/*****************************************************************************************************/
/* Data connection setup related */

static int prv_config_data_channel_route(int enable, int cid, int nid)
{
    char option[128];
    int len;

    if (cid <= 0 || cid > APN_PROFILE_MAX) {
        AFLOG_ERR("prv_config_data_channel_route:bad cid %d", cid);
        return -1;
    }

    len = snprintf(option, sizeof(option), "=%d,1,\"%s%d\",\"%s%d\",2,%d",
            enable, AT_ROUTE_CID_PATH, nid, AT_ROUTE_TID_PATH, nid, cid);

    if (len >= sizeof(option)) {
        AFLOG_ERR("config_data_channel_route");
        return -1;
    }

    if (at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_DATA_CHANNEL_ROUTE, option, 0) != AT_RESULT_SUCCESS)
        return -1;

    return 0;
}

#define PROFILE_LOCK   0
#define PROFILE_UNLOCK 1

static int prv_lock_reserved_profiles(int lock)
{
    int res = at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_PDN_PROFILE, (lock != PROFILE_LOCK ? "=2,1" : "=2,0"), 0);
    if (res != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("prv_lock_reserved_profile:res=%d,lock=%d:can't lock/unlock reserved profiles", res, lock);
        return -1;
    }
    return 0;
}

static int prv_config_pdn_profile(int cid, const char *apn, const char *protocol)
{
    char option[128];
    int len, res;

    len = snprintf(option, sizeof(option), "=%d,\"%s\",\"%s\"", cid, protocol, apn);
    if (len >= sizeof(option)) {
        AFLOG_ERR("config_pdn_profile::option buf too small::required=%d", len);
        return -1;
    }

    res = at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_PDN_PROFILE, option, 0);
    if (res != AT_RESULT_SUCCESS) {
        return -1;
    }

    return 0;
}

static int prv_config_pdn_auth(int cid, const char *auth_type,
        const char *user, const char *password)
{
    char option[64];
    int len;

    len = snprintf(option, sizeof(option), "=%s,%d,\"%s\",\"%s\"", auth_type, cid, user, password);
    if (len >= sizeof(option)) {
        AFLOG_ERR("prv_config_pdn_auth::option buf too small::required=%d", len);
        return -1;
    }

    if (at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_PDN_AUTH_SETTING, option, 0))
        return -1;

    return 0;
}


#define AT_OPT_RAW_IP "M-RAW_IP"
static int prv_enter_data_state(int cid)
{
    char option[64];
    int len;

    if (cid > APN_PROFILE_MAX)
        return -1;

    len = snprintf(option, sizeof(option), "=\"%s\",%d", AT_OPT_RAW_IP, cid);
    if (len >= sizeof(option)) {
        AFLOG_ERR("prv_enter_data_state::option buffer too small::required=%d", len);
        return -1;
    }

    if (at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_ENTER_DATA_STATE, option, 0) != AT_RESULT_SUCCESS)
        return -1;

    return 0;
}

static pdn_protocol prv_parse_pdn_protocol(const char *protocol)
{
    if (strcmp(protocol, "IP") == 0) {
        return PDN_PROTOCOL_IP;
    } else if (strcmp(protocol, "IPV6") == 0) {
        return PDN_PROTOCOL_IPV6;
    } else if (strcmp(protocol, "IPV4V6") == 0) {
        return PDN_PROTOCOL_IPV4V6;
    }
    return PDN_PROTOCOL_INVALID;
}

static apn_profile_t * prv_prepare_apn_profile(ril_data_call_request_t *req)
{
    apn_profile_t *profile;
    int i;

    AFLOG_DEBUG3("req apn=%s protocol=%s", req->apn, req->protocol);
    /* return matching profile already exists */
    for (i = 0; i < APN_PROFILE_MAX; i++) {
        profile = &sProfiles[i];
        if (profile->valid) {
            AFLOG_DEBUG3("profile=%d apn=%s protocol=%s", i, profile->apn, profile->protocol);
            if (!strncmp(profile->apn, req->apn, sizeof(profile->apn))
                && !strncmp(profile->protocol, req->protocol, sizeof(profile->protocol))
                && !strcmp(req->auth_type, "")
                && !strcmp(req->user, "")
                && !strcmp(req->password, "")) {
                sConnectionId = profile->cid;
                return profile;
            }
        }
    }

    AFLOG_INFO("prv_prepare_apn_profile:No match found. Updating default");

    prv_lock_reserved_profiles(PROFILE_UNLOCK);

    /* if no match, modify and return default profile */
    profile = &sProfiles[APN_PROFILE_DEFAULT];
    if (prv_config_pdn_profile(profile->cid, req->apn, req->protocol) != 0) {
        AFLOG_ERR("prv_config_apn_profile::failed to configure pdn profile");
        return NULL;
    }

    strncpy(profile->apn, req->apn, sizeof(profile->apn));
    strncpy(profile->protocol, req->protocol, sizeof(profile->protocol));

    if (prv_config_pdn_auth(profile->cid, req->auth_type, req->user, req->password) != 0) {
        AFLOG_ERR("prv_config_apn_profile::failed to configure pdn auth");
        return NULL;
    }

    strncpy(profile->auth_type, req->auth_type, sizeof(profile->auth_type));
    strncpy(profile->user, req->user, sizeof(profile->user));
    strncpy(profile->password, req->password, sizeof(profile->password));

    prv_lock_reserved_profiles(PROFILE_LOCK);

    sConnectionId = profile->cid;
    return profile;
}


static int prv_is_valid_ip_addr(char *ip_addr)
{
    struct in_addr addr_v4;
    struct in6_addr addr_v6;

    if (!strcmp("0.0.0.0", ip_addr))
        return AF_UNSPEC;

    if (inet_pton(AF_INET, ip_addr, &addr_v4) == 1)
        return AF_INET;

    if (inet_pton(AF_INET6, ip_addr, &addr_v6) == 1)
        return AF_INET6;

    return AF_UNSPEC;
}

static int prv_update_pdp_address(data_connection_t *conn, int cid)
{
    char *line;
    if (at_send_cmd_1_int(AT_RSP_TYPE_PREFIX, AT_CMD_IP_SETTING, cid, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_update_pdp_address::failed to get ip");
        return RIL_ERR_NONFATAL;
    }

    conn->ip_v4[0] = '\0';
    conn->ip_v6[0] = '\0';

    while ((line = at_rsp_next_line()) != NULL) {
        char *token[3];
        int num_tokens, af;
        AFLOG_DEBUG3("prv_update_pdp_address::line::%s", line);
        num_tokens = at_tokenize_line(line, ',', token, ARRAY_SIZE(token));
        if (num_tokens < 1) {
            AFLOG_ERR("prv_update_pdp_address::invalid num tokens::%d", num_tokens);
        }

        if (cid != strtol(token[0], NULL, 10)) {
            AFLOG_DEBUG3("prv_update_pdp_address::cid doesn't match::expected=%d,received=%s", cid, token[0]);
            continue;
        }

        if (num_tokens > 1) {
            af = prv_is_valid_ip_addr(token[1]);
            if (af == AF_INET) {
                strncpy(conn->ip_v4, token[1], sizeof(conn->ip_v4));
            } else if (af == AF_INET6) {
                strncpy(conn->ip_v6, token[1], sizeof(conn->ip_v6));
            }
        }

        if (num_tokens > 2) {
            af = prv_is_valid_ip_addr(token[2]);
            if (af == AF_INET) {
                strncpy(conn->ip_v4, token[2], sizeof(conn->ip_v4));
            } else if (af == AF_INET6) {
                strncpy(conn->ip_v6, token[2], sizeof(conn->ip_v6));
            }
        }
    }

    if (conn->ip_v4[0] == '\0' && conn->ip_v6[0] == '\0') {
        AFLOG_ERR("prv_update_pdp_address::ipv4 and ipv6 address both unset");
        return RIL_ERR_NONFATAL;
    }

    return RIL_ERR_NONE;
}

static int prv_update_pdp_dns(int cid)
{
    char *line;

    data_connection_t *conn;
    if (at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_DNS_REQUEST, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_update_pdp_dns:: failed to query DNS");
        return RIL_ERR_NONFATAL;
    }

    conn = &sConnection;
    conn->dns1_v4[0] = '\0';
    conn->dns2_v4[0] = '\0';
    conn->dns1_v6[0] = '\0';
    conn->dns2_v6[0] = '\0';

    while ((line = at_rsp_next_line()) != NULL) {
        char *token[3];
        int num_tokens, af, i;
        AFLOG_DEBUG3("prv_update_pdp_dns::line::%s", line);
        num_tokens = at_tokenize_line(line, ',', token, ARRAY_SIZE(token));
        if (num_tokens < 1) {
            AFLOG_ERR("prv_update_pdp_dns::invalid num tokens::%d", num_tokens);
            continue;
        }

        if (cid != strtol(token[0], NULL, 10)) {
            AFLOG_DEBUG3("prv_update_pdp_dns::cid doesn't match::expected=%d,received=%s", cid, token[0]);
            continue;
        }

        for (i = 1; i < num_tokens; i++) {
            char *addr;
            addr = token[i];
            af = prv_is_valid_ip_addr(addr);
            if (af == AF_INET) {
                if (strcmp(conn->dns1_v4, addr) && strcmp(conn->dns2_v4, addr)) {
                    /* doesn't match existing primary or secondary v4 entry */
                    if (*conn->dns1_v4 == '\0') {
                        strncpy(conn->dns1_v4, addr, sizeof(conn->dns1_v4));
                    } else if (*conn->dns2_v4 == '\0') {
                        strncpy(conn->dns2_v4, addr, sizeof(conn->dns2_v4));
                    } else {
                        AFLOG_DEBUG1("prv_update_pdp_dns::ignoring, both dns1_v4 and dns2_v4 set");
                    }
                }
            } else if (af == AF_INET6) {
                if (strcmp(conn->dns1_v6, addr) && strcmp(conn->dns2_v6, addr)) {
                    /* doesn't match existing primary or secondary v6 entry */
                    if (*conn->dns1_v6 == '\0') {
                        strncpy(conn->dns1_v6, addr, sizeof(conn->dns1_v6));
                    } else if (*conn->dns2_v6 == '\0') {
                        strncpy(conn->dns2_v6, addr, sizeof(conn->dns2_v6));
                    } else {
                        AFLOG_DEBUG1("prv_update_pdp_dns::ignoring, both dns1_v6 and dns2_v6 set");
                    }
                }
            }
        }
    }

    if (conn->dns1_v4[0] == '\0' && conn->dns1_v6[0] == '\0') {
        AFLOG_WARNING("prv_update_pdp_dns::dns1_v4 and dns1_v6 both unset");
        strcpy(conn->dns1_v4, "8.8.8.8");
        strcpy(conn->dns2_v4, "8.8.4.4");
        return RIL_ERR_NONE;
    }

    return RIL_ERR_NONE;
}



int ril_activate_data_call(ril_data_call_response_t *dataCallRsp)
{
    int cid;
    pdn_protocol proto;
    int err = RIL_ERR_NONE;

    if (dataCallRsp == NULL) {
        return RIL_ERR_FATAL;
    }

    if (sConnection.state != DATA_CONNECTION_STATE_IDLE) {
        AFLOG_ERR("ril_activate_data_call::no idle connections available");
        return RIL_ERR_NONFATAL;
    }

    cid = sConnectionId;
    if (cid < 0) {
        AFLOG_ERR("ril_activate_data_call_cid::APN was not set up correctly");
        return RIL_ERR_FATAL;
    }

    at_start_cmds();

    /* enable channel route */
    AFLOG_DEBUG3("ril_activate_data_call::enable channel route cid=%d nid=%d", cid, sConnection.nid);
    if (prv_config_data_channel_route(1, cid, sConnection.nid) != 0) {
        AFLOG_ERR("ril_activate_data_call::failed to configure data channel route");
        err = RIL_ERR_FATAL;
        goto error;
    }

    /* set dns */
    AFLOG_DEBUG3("ril_activate_data_call::setting up dns");
    proto = prv_parse_pdn_protocol(sProfiles[cid].protocol);
    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_DNS_REQUEST, cid, proto, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("ril_activate_data_call::failed to setup data call");
        err = RIL_ERR_NONFATAL;
        goto error_unroute;
    }

    /* activate pdn */
    AFLOG_DEBUG3("ril_activate_data_call::activating pdn");
    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_PDN_ACTIVATION, 1, cid, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("ril_activate_data_call::failed to activate pdn");
        err = RIL_ERR_NONFATAL;
        goto error_unroute;
    }

    at_end_cmds();
    sleep(2);
    at_start_cmds();

    /* get ip */
    AFLOG_DEBUG3("ril_activate_data_call::getting ip address");
    err = prv_update_pdp_address(&sConnection, cid);
    if (err < 0) {
        AFLOG_ERR("ril_activate_data_call::failed to update pdp address");
        err = RIL_ERR_NONFATAL;
        goto error_deactivate;
    }

    /* get dns address */
    AFLOG_DEBUG3("ril_activate_data_call::updating dns address");
    err = prv_update_pdp_dns(cid);
    if (err < 0) {
        AFLOG_ERR("prv_update_pdp_dns::failed to update pdp dns");
        err = RIL_ERR_NONFATAL;
        goto error_deactivate;
    }

    /* enter data state */
    AFLOG_DEBUG3("ril_activate_data_call::entering data state");
    if (prv_enter_data_state(cid) != 0) {
        AFLOG_ERR("ril_activate_data_call::failed to enter data state");
        err = RIL_ERR_NONFATAL;
        goto error_deactivate;
    }

    sConnection.cid = cid;
    sConnection.state = DATA_CONNECTION_STATE_ACTIVE;

    strcpy(dataCallRsp->ip_v4, sConnection.ip_v4);
    strcpy(dataCallRsp->ip_v6, sConnection.ip_v6);
    strcpy(dataCallRsp->dns1_v4, sConnection.dns1_v4);
    strcpy(dataCallRsp->dns2_v4, sConnection.dns2_v4);
    strcpy(dataCallRsp->dns1_v6, sConnection.dns1_v6);
    strcpy(dataCallRsp->dns2_v6, sConnection.dns2_v6);
    dataCallRsp->subnet_v4 = 24;
    dataCallRsp->subnet_v6 = 64;

    at_end_cmds();

    return RIL_ERR_NONE;

error_deactivate:
    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_PDN_ACTIVATION, 1, cid, 0)
            != AT_RESULT_SUCCESS) {
        AFLOG_ERR("ril_activate_data_call::failed to deactivate pdp context");
    }

error_unroute:
    if (prv_config_data_channel_route(0, cid, sConnection.nid) != 0) {
        AFLOG_ERR("ril_activate_data_call::failed to tear down data channel route");
        goto error;
    }

error:
    at_end_cmds();

    return err;
}

int ril_deactivate_data_call(void)
{
    int retVal = RIL_ERR_NONE;

    at_start_cmds();

    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_PDN_ACTIVATION, 0, sConnection.cid, 0)
            != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_ril_deactivate_data_call::failed to deactivate pdp context");
        retVal = RIL_ERR_FATAL;
        goto exit;
    }

    if (prv_config_data_channel_route(0, sConnection.cid, sConnection.nid) != 0) {
        AFLOG_ERR("prv_ril_deactivate_data_call::failed to tear down data channel route");
        retVal = RIL_ERR_FATAL;
        goto exit;
    }
    sConnection.state = DATA_CONNECTION_STATE_IDLE;

exit:
    at_end_cmds();

    return retVal;
}

int ril_get_ps_attach(int *attachedP)
{
    int retVal = RIL_ERR_NONE;

    if (attachedP == NULL) {
        return RIL_ERR_FATAL;
    }

    at_start_cmds();

    /* clear out the camp status */
    memset(sCampStatus, 0, sizeof(sCampStatus));

    /* AT+KCCINFO */
    int result = at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_CAMPED_CELL_INFO, 0);
    if (result != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("ril_get_ps_attach:atfail:cmd=kccinfo:couldn't send command");
        retVal = RIL_ERR_FATAL;
        goto exit;
    }

    char *tokens[40];
    int nt;
    int pos = 0;

    if ((nt = at_tokenize_line(at_rsp_next_line(), ',', tokens, ARRAY_SIZE(tokens))) < 4) {
        AFLOG_WARNING("ril_get_ps_attach:parse:cmd=kccinfo,nt=%d:failed to parse tokens", nt);
        retVal = RIL_ERR_NONFATAL;
        goto exit;
    } else {
        pos += SNPRINTF(&sCampStatus[pos], sizeof(sCampStatus) - pos, "CI=%s RAC=%s TAC=%s", tokens[1], tokens[2], tokens[3]);
    }
    if (!strcmp(tokens[3], "FFFF")) {
        sBars = 0; /* not camped */
    }

    /* AT+XCESQ */
    result = at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_SIGNAL_QUALITY, 0);
    if (result != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("ril_get_ps_attach:atfail:cmd=cesq:couldn't send command");
        retVal = RIL_ERR_FATAL;
        goto exit;
    }

    if ((nt = at_tokenize_line(at_rsp_next_line(), ',', tokens, ARRAY_SIZE(tokens))) != 8) {
        AFLOG_WARNING("ril_get_ps_attach:parse:cmd=cesq,nt=%d:failed to parse tokens", nt);
        retVal = RIL_ERR_NONFATAL;
        goto exit;
    }
    float rsrq=-999.0, rssnr=-999.0;
    int16_t rsrp = -999;

    if (tokens[5][0]) {
        rsrq = ((float)strtol(tokens[5], NULL, 10)) / 2.0 - 19.5;
    }
    if (tokens[6][0]) {
        rsrp = strtol(tokens[6], NULL, 10) - 140;
    }
    if (tokens[7][0]) {
        rssnr = ((float)strtol(tokens[7], NULL, 10)) / 2.0;
    }
    pos += SNPRINTF(&sCampStatus[pos], sizeof(sCampStatus) - pos, " RSRQ=%.1f RSRP=%d RSSNR=%.1f",
                    rsrq, rsrp, rssnr);

    /* calculate bars based on RSRP */
    if (rsrp > -85) {
        sBars = 5;
    } else if (rsrp > -95) {
        sBars = 4;
    } else if (rsrp > -105) {
        sBars = 3;
    } else if (rsrp > -115) {
        sBars = 2;
    } else {
        sBars = 1;
    }

    /* AT+CGATT */
    result = at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_PS_ATTACH, 0);
    if (result != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("ril_get_ps_attach:atfail:cmd=cgatt:couldn't send command");
        retVal = RIL_ERR_FATAL;
        goto exit;
    }

    if ((nt = at_tokenize_line(at_rsp_next_line(), ',', tokens, ARRAY_SIZE(tokens))) != 1) {
        AFLOG_WARNING("ril_get_ps_attach:parse:cmd=cgatt,nt=%d:failed to parse tokens", nt);
        retVal = RIL_ERR_NONFATAL;
        goto exit;
    }
    if (tokens[0][0] == '1') {
        *attachedP = 1;
    } else if (tokens[0][0] == '0') {
        *attachedP = 0;
    } else {
        AFLOG_WARNING("ril_get_ps_attach:attach:attached=%s:bad attach value", tokens[0]);
        retVal = RIL_ERR_NONFATAL;
        goto exit;
    }

    if (*attachedP == 0) {
        /* don't gather serving and neighbor cell info */
        retVal = RIL_ERR_NONE;
        goto exit;
    }

    /* AT+KCELL */
    result = at_send_cmd_1_int(AT_RSP_TYPE_PREFIX, AT_CMD_CELL_ENVIRONMENT_INFO, 0, 0);
    if (result != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("ril_get_ps_attach:atfail:cmd=xcellinfo:couldn't send command");
        retVal = (result == AT_RESULT_TIMEDOUT ? RIL_ERR_NONE : RIL_ERR_NONFATAL);
        goto exit;
    }

    /* clean out the old strings */
    memset(sServingStatus, 0, sizeof(sServingStatus));
    memset(sNeighborStatus, 0, sizeof(sNeighborStatus));

    char *line;
    while ((line = at_rsp_next_line()) != NULL) {
        nt = at_tokenize_line(line, ',', tokens, ARRAY_SIZE(tokens));
        int nf = 0, nbr_count = 0;
        int nc = atoi(tokens[nf++]);
        if (nc == 0) {
            continue;
        }

        while (nf < nt) {
            int cell_type = atoi(tokens[nf++]);
            if (cell_type == 5 && nf + 7 <= nt) { /* serving cell; seven fields */
                pos = 0;
                pos += SNPRINTF(&sServingStatus[pos], sizeof(sServingStatus) - pos,
                                "PLMN=%s LTECI=%s PCID=%s TAC=%s RSRP=%s RSRQ=%s TA=%s",
                                tokens[nf], tokens[nf+1], tokens[nf+2], tokens[nf+3], tokens[nf+4], tokens[nf+5], tokens[nf+6]);
                nf += 7;
            } else if (cell_type == 6 && nf + 4 <= nt) { /* neighbor cell; four fields */
                if (nbr_count == 0) {
                    pos = 0;
                    pos += SNPRINTF(&sNeighborStatus[pos], sizeof(sNeighborStatus) - pos,
                                "EARFCN=%s PCID=%s RSRP=%s RSRQ=%s", tokens[nf], tokens[nf+1], tokens[nf+2], tokens[nf+3]);
                } else {
                    pos += SNPRINTF(&sNeighborStatus[pos], sizeof(sNeighborStatus) - pos,
                                " EARFCN=%s PCID=%s RSRP=%s RSRQ=%s", tokens[nf], tokens[nf+1], tokens[nf+2], tokens[nf+3]);
                }
                nf += 4;
                nbr_count++;
            }
        }
    }
    AFLOG_DEBUG3("srv_status=\"%s\"\n", sServingStatus);
    AFLOG_DEBUG3("nbr_status=\"%s\"\n", sNeighborStatus);

exit:
    at_end_cmds();

    return retVal;
}

char *ril_get_sim_status(void)
{
    return sSimStatus;
}

char *ril_get_camp_status(void)
{
    return sCampStatus;
}

char *ril_get_serving_status(void)
{
    return sServingStatus;
}

char *ril_get_neighbor_status(void)
{
    return sNeighborStatus;
}

uint8_t ril_get_bars(void)
{
    return sBars;
}

char *ril_get_iccid(void)
{
    return sIccid;
}

void ril_shutdown(void)
{
    at_shutdown();

    strcpy(sSimStatus, POWER_OFF_STATUS);
    sCampStatus[0] = '\0';
    sServingStatus[0] = '\0';
    sNeighborStatus[0] = '\0';
    sBars = 0;

    sEventBase = NULL;
}

int ril_init(struct event_base *base, ril_event_callback_t callback, void *context)
{
    int i;

    sRilEventCallback = callback;
    sRilEventContext = context;
    sEventBase = base;

    /* Initialize data connection state */
    memset(&sConnection, 0, sizeof(sConnection));
    sConnection.nid = 0;
    sConnection.state = DATA_CONNECTION_STATE_IDLE;

    /* Initialize profile CID's */
    for (i = 0; i < APN_PROFILE_MAX; i++) {
        apn_profile_t *profile = &sProfiles[i];
        profile->valid = 0;
        *(int *)&profile->cid = i + 1;
    }

    at_unsol_def_t defs[] = {
        { AT_UNSOL_PS_EVENT, prv_on_ps_event },
        { AT_CMD_PS_STATUS_LTE, prv_on_ps_status_lte },
        { AT_UNSOL_REGISTRATION_EVENT, prv_on_registration_event },
        { AT_CMD_SIGNAL_QUALITY, prv_on_signal_quality }
    };
    at_init("/dev/ttyACM0", base, defs, ARRAY_SIZE(defs), NULL);

    if (prv_modem_init() < 0) {
        goto error;
    }

    return 0;

error:
    ril_shutdown();

    return RIL_ERR_FATAL;
}

