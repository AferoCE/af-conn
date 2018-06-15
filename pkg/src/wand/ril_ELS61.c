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
#include <ctype.h>

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

#define AT_CMD_ECHO                    "E"
#define AT_CMD_PS_EVENT_REPORT         "+CGEREP"
#define AT_CMD_PS_STATUS_LTE           "+CEREG"
#define AT_CMD_DNS_REQUEST             "+XDNS"
#define AT_CMD_IP_SETTING              "+CGPADDR"
#define AT_CMD_ENTER_DATA_STATE        "^SWWAN"
#define AT_CMD_PDN_PROFILE             "+CGDCONT"
#define AT_CMD_PDN_AUTH_SETTING        "^SGAUTH"
#define AT_CMD_SET_ERROR_REPORT        "+CMEE"
#define AT_CMD_NETWORK_SELECTION       "+COPS"
#define AT_CMD_PS_ATTACH               "+CGATT"
#define AT_CMD_ICCID                   "+CCID"
#define AT_CMD_IMEI                    "+CGSN"
#define AT_CMD_SV                      "+CGMR"
#define AT_CMD_IMSI                    "+CIMI"
#define AT_CMD_SERVING_CELL_INFO       "^SMONI"
#define AT_CMD_CELL_ENVIRONMENT_INFO   "^SMONP"

#define AT_UNSOL_PHONEBOOK_READY       "+PBREADY"
#define AT_UNSOL_PS_EVENT              "+CGEV"
#define AT_UNSOL_REGISTRATION_EVENT    "+CEREG"
#define AT_UNSOL_SIGNAL_QUALITY        "+XCESQI"

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
static ril_wan_status_t sWanStatus = {
    .rsrp = -999,
    .psState = RIL_PS_STATE_UNKNOWN,
    .regState = RIL_REG_STATE_UNKNOWN,
    .roamingState = RIL_ROAMING_STATE_UNKNOWN,
    .simStatus = RIL_SIM_STATUS_UNKNOWN,
    .rat = RIL_RAT_UNKNOWN
};

static pthread_mutex_t sWanStatusMutex = PTHREAD_MUTEX_INITIALIZER;

static apn_profile_t * prv_prepare_apn_profile(ril_data_call_request_t *req);

static int sConnectionId = -1;
static int sPhoneBookReady = 0;

#if 0
static char sNeighborStatus[256] = "";
#endif

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

static void prv_on_phonebook_ready(char *rest, void *context)
{
    sPhoneBookReady = 1;
}

static void prv_on_ps_event(char *rest, void *context)
{
    char *token[5];
    int num_tokens;

    AFLOG_DEBUG3("on_cgev:rest=\"%s\"", rest);
    num_tokens = at_tokenize_line(rest, ' ', token, ARRAY_SIZE(token));

    /* sConnection is not protected. We assume int is atomic */
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

static void prv_on_registration_event(char *rest, void *context)
{
    AFLOG_DEBUG3("on_cereg:rest=\"%s\"", rest);
    char *tokens[4];
    int nt;
    if ((nt = at_tokenize_line(rest, ',', tokens, ARRAY_SIZE(tokens))) < 0) {
        AFLOG_WARNING("prv_on_ps_status_lte_parse:nt=%d:failed to parse tokens", nt);
    } else {
        if (nt > 0) {
            ril_lock_wan_status();
            int regState = atoi(tokens[0]);
            switch(regState) {
                case 0 :
                    sWanStatus.regState = RIL_REG_STATE_NOT_REGISTERED;
                    sWanStatus.roamingState = RIL_ROAMING_STATE_UNKNOWN;
                case 1 :
                    sWanStatus.regState = RIL_REG_STATE_REGISTERED;
                    sWanStatus.roamingState = RIL_ROAMING_STATE_HOME;
                    break;
                case 2 :
                    sWanStatus.regState = RIL_REG_STATE_SEARCHING;
                    sWanStatus.roamingState = RIL_ROAMING_STATE_UNKNOWN;
                    break;
                case 3 :
                    sWanStatus.regState = RIL_REG_STATE_DENIED;
                    sWanStatus.roamingState = RIL_ROAMING_STATE_UNKNOWN;
                    break;
                default :
                    AFLOG_WARNING("prv_on_ps_status_lte_regState:regState=%d", regState);
                case 4 :
                    sWanStatus.regState = RIL_REG_STATE_UNKNOWN;
                    sWanStatus.roamingState = RIL_ROAMING_STATE_UNKNOWN;
                    break;
                case 5 :
                    sWanStatus.regState = RIL_REG_STATE_REGISTERED;
                    sWanStatus.roamingState = RIL_ROAMING_STATE_ROAMING;
                    break;
            }
            ril_unlock_wan_status();
        }
    }
}

static void prv_on_signal_quality(char *rest, void *context)
{
    AFLOG_DEBUG3("on_xcesq:rest=\"%s\"", rest);
    char *tokens[7];
    int nt;

    if ((nt = at_tokenize_line(rest, ',', tokens, ARRAY_SIZE(tokens))) != 7) {
        AFLOG_WARNING("prv_on_signal_quality_parse:nt=%d:failed to parse tokens", nt);
    } else {
        int16_t rsrqX10=-9990, rssnrX10=-9990;
        int16_t rsrp = -999;
        uint8_t bars;

        if (tokens[4][0]) {
            rsrqX10 = strtol(tokens[4], NULL, 10) * 5 - 195;
        }
        if (tokens[5][0]) {
            rsrp = strtol(tokens[5], NULL, 10) - 140;
        }
        if (tokens[6][0]) {
            rssnrX10 = strtol(tokens[6], NULL, 10) * 5;
        }
        /* calculate bars based on RSRP */
        if (rsrp > -85) {
            bars = 5;
        } else if (rsrp > -95) {
            bars = 4;
        } else if (rsrp > -105) {
            bars = 3;
        } else if (rsrp > -115) {
            bars = 2;
        } else {
            bars = 1;
        }

        ril_lock_wan_status();

        sWanStatus.rsrp = rsrp;
        sWanStatus.rsrqX10 = rsrqX10;
        sWanStatus.rssnrX10 = rssnrX10;
        sWanStatus.bars = bars;

        ril_unlock_wan_status();
    }
}

/* sWanStatus must be locked when this is called */
static void prv_set_rat(char act)
{
    switch(act) {
        case '0':
        case '1':
            sWanStatus.rat = RIL_RAT_GSM;
            break;
        case '2':
        case '4':
        case '5':
        case '6':
            sWanStatus.rat = RIL_RAT_UMTS;
            break;
        case '3':
            sWanStatus.rat = RIL_RAT_EGPRS;
            break;
        case '7':
            sWanStatus.rat = RIL_RAT_LTE;
            break;
        default:
            break;
    }
}

static void prv_on_network_selection(char *rest, void *context)
{
    AFLOG_DEBUG3("on_cops:rest=\"%s\"", rest);
    char *tokens[4];
    int nt;
    if ((nt = at_tokenize_line(rest, ',', tokens, ARRAY_SIZE(tokens))) < 0) {
        AFLOG_WARNING("ril_get_ps_attach:parse:cmd=cops,nt=%d:failed to parse tokens", nt);
    } else {
        if (nt > 3) {
            ril_lock_wan_status();
            if (isdigit(tokens[2][0])) { /* This is in numeric form */
                sWanStatus.mcc[0] = tokens[2][0];
                sWanStatus.mcc[1] = tokens[2][1];
                sWanStatus.mcc[2] = tokens[2][2];
                sWanStatus.mcc[3] = '\0';
                sWanStatus.mnc[0] = tokens[2][3];
                sWanStatus.mnc[1] = tokens[2][4];
                sWanStatus.mnc[2] = tokens[2][5]; /* may be '\0' */
                sWanStatus.mnc[3] = '\0';
            } else { /* This is the short name form */
                strncpy(sWanStatus.plmn, tokens[2], sizeof(sWanStatus.plmn));
                sWanStatus.plmn[sizeof(sWanStatus.plmn) - 1] = '\0';
            }
            prv_set_rat(tokens[3][0]);
            ril_unlock_wan_status();
        }
    }
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
#define COPS_ERR_BUSY 256

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

    int waiting;
    do {
        waiting = 0;
        AFLOG_INFO("prv_select_network:timeout=%d", SELECT_NETWORK_TIMEOUT);
        int res = at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_NETWORK_SELECTION, "=0", SELECT_NETWORK_TIMEOUT);
        if (res != AT_RESULT_SUCCESS) {
            int err = at_rsp_error();
            AFLOG_WARNING("prv_select_network:res=%d:can't select network", res, err);
            if (err == COPS_ERR_BUSY) {
                waiting = 1;
                sleep(1);
            } else {
                goto exit;
            }
        }
    } while (waiting);

    retVal = 0;

exit:
    at_end_cmds();

    return retVal;
}

ril_wan_status_t *ril_lock_wan_status(void)
{
    pthread_mutex_lock(&sWanStatusMutex);
    return &sWanStatus;
}

void ril_unlock_wan_status(void)
{
    pthread_mutex_unlock(&sWanStatusMutex);
}

#define CME_ERROR_NO_SIM 10 // returned by the sierra modem when sim is not present
static int prv_modem_init(void)
{
    int retVal = -1;

    sConnectionId = -1; /* unset the connection ID */
    sPhoneBookReady = 0;

    at_start_cmds();

    /* Disable echo */
    if (at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_ECHO, "0", 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to configure echo");
        goto error;
    }

    /* Report errors numerically */
    if (at_send_cmd_1_int(AT_RSP_TYPE_OK, AT_CMD_SET_ERROR_REPORT, AT_OPT_ERROR_NUMERIC, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to configure error report");
        goto error;
    }

    /* Register for LTE packet switch status event (CEREG) */
    if (at_send_cmd_1_int(AT_RSP_TYPE_OK, AT_CMD_PS_STATUS_LTE, AT_OPT_PS_REPORT_ENABLE_ALL, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init:cereg:failed to configure ps status reporting");
        goto error;
    }

    /* Register for packet switch status event (CGEV) for network disconnect event */
    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_PS_EVENT_REPORT, AT_OPT_PS_EVENT_REPORT, 0, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init:cgerep:failed to configure ps event reporting");
        goto error;
    }

    /* Set network name type to short alphanumeric */
    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_NETWORK_SELECTION, 3, 1, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init:cmd=cops=3,1");
        goto error;
    }

    /* Get the IMEI */
    if (at_send_cmd(AT_RSP_TYPE_NO_PREFIX, AT_CMD_IMEI, NULL, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to get IMEI");
        goto error;
    }
    ril_lock_wan_status();
    strncpy(sWanStatus.imeisv, at_rsp_next_line(), sizeof(sWanStatus.imeisv));
    sWanStatus.imeisv[sizeof(sWanStatus.imeisv) - 1] = '\0';
    int imeiLen = strlen(sWanStatus.imeisv);
    ril_unlock_wan_status();

    /* Get the software version */
    if (at_send_cmd(AT_RSP_TYPE_NO_PREFIX, AT_CMD_SV, NULL, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init::failed to get SV");
        goto error;
    }
    char *token[2];
    int n = at_tokenize_line(at_rsp_next_line(), ' ', token, ARRAY_SIZE(token));
    if (n != ARRAY_SIZE(token)) {
        AFLOG_ERR("prv_modem_init::failed to parse SV");
        return -1;
    }
    /* format:REVISION xx.xxx; strip off '.' and all that follows */
    if (imeiLen + 3 < sizeof(sWanStatus.imeisv)) {
        ril_lock_wan_status();
        sWanStatus.imeisv[imeiLen] = token[1][0];
        sWanStatus.imeisv[imeiLen + 1] = token[1][1];
        sWanStatus.imeisv[imeiLen + 2] = '\0';
        ril_unlock_wan_status();
    }

    /* Get the ICCID and detect the SIM */
    int res = at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_ICCID, NULL, 0);
    if (res == AT_RESULT_SUCCESS) {
        ril_lock_wan_status();
        sWanStatus.simStatus = RIL_SIM_STATUS_PRESENT;
        strncpy(sWanStatus.iccid, at_rsp_next_line(), sizeof(sWanStatus.iccid));
        sWanStatus.iccid[sizeof(sWanStatus.iccid) - 1] = '\0';
        ril_unlock_wan_status();
    } else {
        ril_lock_wan_status();
        if (res == AT_RESULT_CME_ERROR && at_rsp_error() == CME_ERROR_NO_SIM) {
            AFLOG_ERR("prv_modem_init_iccid_no_sim::sim not present");
            sWanStatus.simStatus = RIL_SIM_STATUS_ABSENT;
        } else {
            AFLOG_ERR("prv_modem_init_iccid_sim:res=%d,err=%d", res, at_rsp_error());
            sWanStatus.simStatus = RIL_SIM_STATUS_ERROR;
        }
        ril_unlock_wan_status();
        goto error;
    }

    /* Get the IMSI */
    if (at_send_cmd(AT_RSP_TYPE_NO_PREFIX, AT_CMD_IMSI, NULL, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("prv_modem_init_imsi:err=%d:can't get imsi",at_rsp_error());
        goto error;
    }
    ril_lock_wan_status();
    strncpy(sWanStatus.imsi, at_rsp_next_line(), sizeof(sWanStatus.imsi));
    sWanStatus.imsi[sizeof(sWanStatus.imsi) - 1] = '\0';
    ril_unlock_wan_status();

    if (prv_update_apn_profile_cache() != 0) {
        AFLOG_ERR("prv_modem_init::failed to update apn profile cache");
        goto error;
    }

    /* wait for the phone book to be ready */
    int i = 0;
    while (sPhoneBookReady == 0) {
        i++;
        if ((i & 0x1f) == 0) {
            AFLOG_INFO("prv_modem_init_wait_pb_ready:i=%d", i);
        }
        if (at_send_cmd(AT_RSP_TYPE_OK, "", NULL, 0) != AT_RESULT_SUCCESS) {
            AFLOG_ERR("prv_modem_init_at:err=%d", at_rsp_error());
            goto error;
        }
        sleep(1);
    }

    retVal = RIL_ERR_NONE;

error:
    at_end_cmds();

    return retVal;
}

/*****************************************************************************************************/
/* Data connection setup related */

#define PROFILE_LOCK   0
#define PROFILE_UNLOCK 1

/* use AT+CGATT to attach/detach from PS network to enable profile change */
static int prv_lock_reserved_profiles(int lock)
{
    int res = at_send_cmd(AT_RSP_TYPE_OK, AT_CMD_PS_ATTACH, (lock == PROFILE_LOCK ? "=1" : "=0"), 0);
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
    int a = 0;

    if (!strcmp(auth_type,"0")) {
        a = 1;
    } else if (!strcmp(auth_type,"1")) {
        a = 2;
    }

    len = snprintf(option, sizeof(option), "=%d,%d,\"%s\",\"%s\"", cid, a, user, password);
    if (len >= sizeof(option)) {
        AFLOG_ERR("prv_config_pdn_auth::option buf too small::required=%d", len);
        return -1;
    }

    if (at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_PDN_AUTH_SETTING, option, 0))
        return -1;

    return 0;
}


static int prv_enter_data_state(int cid, int enter)
{
    char option[64];
    int len;

    if (cid > APN_PROFILE_MAX)
        return -1;

    len = snprintf(option, sizeof(option), "=%d,%d", (enter ? 1 : 0), cid);
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
            AFLOG_DEBUG3("cid=%d apn=%s protocol=%s", profile->cid, profile->apn, profile->protocol);
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

    AFLOG_DEBUG3("ril_activate_data_call::Parse pdn protocol");
    proto = prv_parse_pdn_protocol(sProfiles[cid].protocol);
    if (at_send_cmd_2_int(AT_RSP_TYPE_OK, AT_CMD_DNS_REQUEST, cid, proto, 0) != AT_RESULT_SUCCESS) {
        AFLOG_ERR("ril_activate_data_call::failed to setup data call");
        err = RIL_ERR_NONFATAL;
        goto error;
    }

    /* enter data state */
    AFLOG_DEBUG3("ril_activate_data_call::entering data state");
    if (prv_enter_data_state(cid, 1) != 0) {
        AFLOG_ERR("ril_activate_data_call::failed to enter data state");
        err = RIL_ERR_NONFATAL;
        goto error_deactivate;
    }

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
    if (prv_enter_data_state(cid, 0) != 0) {
        AFLOG_ERR("ril_activate_data_call::failed to exit data state");
    }

error:
    at_end_cmds();

    return err;
}

int ril_deactivate_data_call(void)
{
    int retVal = RIL_ERR_NONE;

    at_start_cmds();

    if (sConnectionId != -1 && sConnection.state == DATA_CONNECTION_STATE_ACTIVE) {
        if (prv_enter_data_state(sConnectionId, 0) != 0) {
            AFLOG_ERR("ril_deactivate_data_call::failed to exit data state");
            retVal = RIL_ERR_FATAL;
        }
        sConnection.state = DATA_CONNECTION_STATE_IDLE;
    }

    at_end_cmds();

    return retVal;
}

static int rsrp_to_bars(int rsrp)
{
    if (rsrp > -85) return 5;
    else if (rsrp > -95) return 4;
    else if (rsrp > -105) return 3;
    else if (rsrp > -115) return 2;
    else return 1;
}

#define SNPRINTF(_buf,_space,_fmt,...) ((_space) > 1 ? snprintf((_buf), (_space), _fmt, ##__VA_ARGS__) : 0)

int sLastMCC=0;
int sLastMNC=0;

int ril_get_ps_attach(void)
{
    int retVal = RIL_ERR_NONE;
    int psAttach = 0;

    at_start_cmds();

    char *tokens[15];
    int nt;

    /* AT+CGATT */
    int result = at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_PS_ATTACH, 0);
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
        psAttach = 1;
        ril_lock_wan_status();
        sWanStatus.psState = 1;
        ril_unlock_wan_status();
    } else if (tokens[0][0] == '0') {
        psAttach = 0;
        ril_lock_wan_status();
        sWanStatus.psState = 0;
        sWanStatus.bars = 0;
        ril_unlock_wan_status();
    } else {
        AFLOG_WARNING("ril_get_ps_attach:attach:attached=%s:bad attach value", tokens[0]);
        retVal = RIL_ERR_NONFATAL;
        goto exit;
    }

    /* Get camped and serving cell information */
    result = at_send_cmd(AT_RSP_TYPE_PREFIX, AT_CMD_SERVING_CELL_INFO, NULL, 0);
    if (result != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("ril_get_ps_attach_at:cmd=smoni:couldn't send command");
        retVal = (result == AT_RESULT_TIMEDOUT ? RIL_ERR_NONE : RIL_ERR_NONFATAL);
        goto exit;
    }

    int mcc = 0, mnc = 0;

    if ((nt = at_tokenize_line(at_rsp_next_line(), ',', tokens, ARRAY_SIZE(tokens))) < 0) {
        AFLOG_WARNING("ril_get_ps_attach_parse:cmd=smoni,nt=%d:failed to parse tokens", nt);
    } else {
        if (nt < 15) {
            AFLOG_WARNING("ril_get_ps_attach_tokens:cmd=smoni,nt=%d:wrong number of tokens for command", nt);
        } else {
            ril_lock_wan_status();
            if (tokens[0][0] == '2') {
                sWanStatus.rat = RIL_RAT_GSM;
            } else if (tokens[0][0] == '4') {
                sWanStatus.rat = RIL_RAT_LTE;
            } else {
                sWanStatus.rat = RIL_RAT_UNKNOWN;
            }
            strncpy(sWanStatus.mcc, tokens[6], 3);
            mcc = strtol(tokens[6], NULL, 10);
            strncpy(sWanStatus.mnc, tokens[7], 3);
            mnc = strtol(tokens[7], NULL, 10);
            sWanStatus.tac = strtol(tokens[8], NULL, 16); /* tac */
            sWanStatus.lac = strtol(tokens[9], NULL, 16); /* lac in hex */
            sWanStatus.pcid = strtol(tokens[10], NULL, 10); /* physical cell ID */
            sWanStatus.rsrp = strtol(tokens[12], NULL, 10); /* rsrp */
            float rsrq;
            sscanf(tokens[13], "%f", &rsrq);
            sWanStatus.rsrqX10 = (int16_t)(rsrq * 10.0);
            sWanStatus.bars = rsrp_to_bars(sWanStatus.rsrp);
            ril_unlock_wan_status();
        }
    }

    if (mcc != sLastMCC || mnc != sLastMNC) {
        result = at_send_query(AT_RSP_TYPE_PREFIX, AT_CMD_NETWORK_SELECTION, 0);
        if (result != AT_RESULT_SUCCESS) {
            AFLOG_WARNING("ril_get_ps_attach_at:cmd=cops:couldn't send command");
            retVal = (result == AT_RESULT_TIMEDOUT ? RIL_ERR_NONE : RIL_ERR_NONFATAL);
            goto exit;
        }
        if ((nt = at_tokenize_line(at_rsp_next_line(), ',', tokens, ARRAY_SIZE(tokens))) != 4) {
            AFLOG_WARNING("ril_get_ps_attach_parse:cmd=cops,nt=%d:failed to parse tokens", nt);
        }
        ril_lock_wan_status();
        strncpy(sWanStatus.plmn, tokens[2], sizeof(sWanStatus.plmn));
        sWanStatus.plmn[sizeof(sWanStatus.plmn)-1] = '\0';
        ril_unlock_wan_status();
        sLastMCC = mcc;
        sLastMNC = mnc;
    }

    /* Get neighbor cell information */
    result = at_send_cmd(AT_RSP_TYPE_NO_PREFIX, AT_CMD_CELL_ENVIRONMENT_INFO, NULL, 0);
    if (result != AT_RESULT_SUCCESS) {
        AFLOG_WARNING("ril_get_ps_attach_at:cmd=smonp:couldn't send command");
        retVal = (result == AT_RESULT_TIMEDOUT ? RIL_ERR_NONE : RIL_ERR_NONFATAL);
        goto exit;
    }

    int pos = 0, nbr_count = 0;

    char *line;
    while ((line = at_rsp_next_line()) != NULL) {
        nt = at_tokenize_line(line, ',', tokens, ARRAY_SIZE(tokens));
        if (nt >= 6) {
            ril_lock_wan_status();
            pos += SNPRINTF(&sWanStatus.neighborInfo[pos], sizeof(sWanStatus.neighborInfo) - pos,
                            (nbr_count == 0 ?  "EARFCN=%s PCID=%s RSRP=%s RSRQ=%s" : " EARFCN=%s PCID=%s RSRP=%s RSRQ=%s"),
                            tokens[0], tokens[4], tokens[2], tokens[1]);
            ril_unlock_wan_status();
            nbr_count++;
        }
    }
    AFLOG_DEBUG3("wan_neighbor_info:%s", &sWanStatus.neighborInfo);

exit:
    at_end_cmds();

    if (retVal == RIL_ERR_NONE) {
        retVal = psAttach;
    }
    return retVal;
}

static void prv_clear_wan_status(void)
{
    memset(&sWanStatus, 0, sizeof(sWanStatus));
    sWanStatus.rsrp = -999;
    sWanStatus.psState = RIL_PS_STATE_UNKNOWN;
    sWanStatus.regState = RIL_REG_STATE_UNKNOWN;
    sWanStatus.roamingState = RIL_ROAMING_STATE_UNKNOWN;
    sWanStatus.simStatus = RIL_SIM_STATUS_UNKNOWN;
    sWanStatus.rat = RIL_RAT_UNKNOWN;
}

void ril_shutdown(void)
{
    at_shutdown();

    prv_clear_wan_status();

    sEventBase = NULL;
}

int ril_init(struct event_base *base, ril_event_callback_t callback, void *context)
{
    int i;

    sRilEventCallback = callback;
    sRilEventContext = context;
    sEventBase = base;

    /* initialize the WAN status */
    prv_clear_wan_status();

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
        { AT_UNSOL_REGISTRATION_EVENT, prv_on_registration_event },
        { AT_UNSOL_SIGNAL_QUALITY, prv_on_signal_quality },
        { AT_CMD_NETWORK_SELECTION, prv_on_network_selection },
        { AT_UNSOL_PHONEBOOK_READY, prv_on_phonebook_ready }
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

