/*
 * wand.c -- WAN Daemon
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Clif Liu and Evan Jeng
 */

#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/event.h>

#include "af_log.h"
#include "af_util.h"
#include "ril.h"
#include "net.h"
#include "server.h"

#define NETIF_NAMES_ALLOCATE
#include "../include/netif_names.h"


#define WAND_RETRY_TIME_MODEM_OFF           3
#define WAND_RETRY_TIME_MODEM_ON            600
#define WAND_RETRY_TIME_DATA_CALL           3
#define WAND_MODEM_CHECK_TIME               10
#define WAND_IDLE_TIME                      10
#define WAND_NUM_PS_FAILURES_UNTIL_REBOOT   60  // Should be approximately 5 minutes

#define _SUB(_x) WAND_EVENT_##_x

#define WAND_EVENTS \
    _SUB(BAD_RIL_EVENT), \
    _SUB(MODEM_UP), \
    _SUB(MODEM_DOWN), \
    _SUB(MODEM_LOCKED), \
    _SUB(DATA_CALL_UP), \
    _SUB(DATA_CALL_DOWN), \
    _SUB(DATA_CALL_LOST), \
    _SUB(PS_ATTACH_LOST), \
    _SUB(RETRY), \
    _SUB(NO_MODEM)

typedef enum {
    WAND_EVENTS,
    WAND_NUM_EVENTS
} wand_event_t;

#undef _SUB
#define _SUB(_x) #_x

static char *s_wand_event_names[] = {
    WAND_EVENTS
};

#undef _SUB

#define WAND_STATES \
    _SUB(OFF), \
    _SUB(WAITING_FOR_DOWN), \
    _SUB(WAITING_FOR_UP), \
    _SUB(WAITING_FOR_DATA), \
    _SUB(DATA)

#define _SUB(_x) WAND_STATE_##_x

typedef enum {
    WAND_STATES,
    WAND_NUM_STATES
} wand_state_t;

#undef _SUB
#define _SUB(_x) #_x

static char *s_wand_state_names[] = {
    WAND_STATES
};

#define WAND_COMMANDS \
    _SUB(NONE), \
    _SUB(MODEM_ON), \
    _SUB(MODEM_OFF), \
    _SUB(ACTIVATE_DATA_CALL), \
    _SUB(REACTIVATE_DATA_CALL), \
    _SUB(CHECK)

#undef _SUB
#define _SUB(_x) WAND_COMMAND_##_x

typedef enum {
    WAND_COMMANDS,
    WAND_COMMAND_NUM_COMMANDS
} wand_command_t;

#undef _SUB
#define _SUB(_x) #_x

static char *s_wand_command_names[] = {
    WAND_COMMANDS
};

#undef _SUB

/* member variables */
static struct event_base *sWandBase = NULL;
static wand_state_t sWandState;
static struct event *sRetryEvent = NULL;
static struct event *sIdleEvent = NULL;
static pthread_t sCmdThread;
static pthread_condattr_t sCmdCondAttr;
static pthread_cond_t sCmdCond;
static pthread_mutex_t sCmdMutex = PTHREAD_MUTEX_INITIALIZER;
static wand_command_t sCmdPending = WAND_COMMAND_NONE;
static uint8_t sCmdThreadCreated = 0;
static uint8_t sCmdCondAttrCreated = 0;
static uint8_t sCmdCondCreated = 0;
static uint8_t sCmdExecuting = 0;
static uint8_t sRilStarted = 0;
static uint8_t sNetworkSetUp = 0;
static uint8_t sNetWatchStarted = 0;
static uint8_t sIpcInitialized = 0;
static uint8_t sDataCallLostWhileActivating = 0;
static ril_data_call_request_t sDataCallReq;
static uint8_t sDataCallReqSetUp = 0;

static uint32_t sNumPsFailures = 0;

static pthread_mutex_t sWandStateMutex = PTHREAD_MUTEX_INITIALIZER;

static void prv_handle_wand_event(wand_event_t event);

#define CARRIER_APN_PATH "/etc/wan/carriers"
#define MAX_COLUMNS 6

static int prv_get_apn_info(char *iccid, ril_data_call_request_t *req)
{
    char buffer[128];

    if (iccid == NULL || req == NULL) {
        errno = EINVAL;
        return -1;
    }

    FILE *f = fopen(CARRIER_APN_PATH, "r");
    if (f == NULL) {
        AFLOG_ERR("parse_apn_file_fopen:path=%s,errno=%d", CARRIER_APN_PATH, errno);
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), f)) {
        char *c[MAX_COLUMNS];
        char *s = buffer;
        int cols;
        for (cols = 0; cols < MAX_COLUMNS; cols++) {
            c[cols] = NULL;
        }


        cols = 0;

        while (cols < MAX_COLUMNS) {
            /* skip leading white space or white space between columns */
            while (*s == ' ' || *s == '\t') {
                s++;
            }

            /* check if comment or end of line */
            if (*s == '\n' || *s == '\0' || *s == '#') {
                break;
            }
            c[cols++] = s;

            /* skip over column and terminate string */
            while (*s != ' ' && *s != '\t' && *s != '\n' && *s != '\0') {
                s++;
            }

            /* check if the line or file ends */
            if (*s == '\n') {
                *s++ = '\0';
                break;
            } else if (*s == '\0') {
                break;
            } else {
                *s++ = '\0';
            }
        }


        /* now we have all columns */
        if (cols > 0) {
            if (cols > 2) {
                if (!strncmp(iccid, c[0], strlen(c[0]))) { // match the prefix
                    strncpy(req->apn, c[1], sizeof(req->apn));
                    req->apn[sizeof(req->apn)-1] = '\0';
                    strncpy(req->protocol, c[2], sizeof(req->protocol));
                    req->protocol[sizeof(req->protocol)-1] = '\0';
                    AFLOG_INFO("parse_apn_file:prefix=%s,apn=%s,protocol=%s", c[0], req->apn, req->protocol);
                    if (cols == MAX_COLUMNS) { /* APN also includes PPP auth parameters */
                        strncpy(req->auth_type, c[3], sizeof(req->auth_type));
                        req->auth_type[sizeof(req->auth_type)-1] = '\0';
                        strncpy(req->user, c[4], sizeof(req->user));
                        req->user[sizeof(req->user)-1] = '\0';
                        strncpy(req->password, c[5], sizeof(req->password));
                        req->password[sizeof(req->password)-1] = '\0';
                        fclose(f);
                        return 0;
                    } else if (cols == 3) {  /* no PPP auth parameters */
                        req->auth_type[0] = '\0';
                        req->user[0] = '\0';
                        req->password[0] = '\0';
                        fclose(f);
                        return 0;
                    } else { /* missing some auth parameters */
                        AFLOG_ERR("parse_apn_file_missing_ppp_cols:prefix=%s,cols=%d", c[0], cols);
                    }
                }
            } else {
                AFLOG_ERR("parse_apn_file_missing_cols:prefix=%s,cols=%d", c[0], cols);
            }
        }
    }
    fclose(f);
    errno = ENOENT;
    return -1;
}


static int prv_set_up_network(ril_data_call_response_t *dataCallRsp)
{
    /* configure WAN network interface */
    if (af_util_system("/usr/bin/wannetwork up \"%s\" 24 \"%s\" \"%s\" \"%s\" 64 \"%s\" \"%s\"",
        dataCallRsp->ip_v4, dataCallRsp->dns1_v4, dataCallRsp->dns2_v4,
        dataCallRsp->ip_v6, dataCallRsp->dns1_v6, dataCallRsp->dns2_v6) < 0) {
        AFLOG_ERR("prv_set_up_network:::failed to bring up WAN network interface");
        return -1;
    }

    return 0;
}

static void prv_on_network_down(int event, void *context)
{
    prv_handle_wand_event(WAND_EVENT_DATA_CALL_LOST);
}

static int prv_shut_down_network(void)
{   /* configure WAN network interface */
    if (af_util_system("/usr/bin/wannetwork down") < 0) {
        AFLOG_ERR("prv_shut_down_network:::failed to shut down network");
        return -1;
    }

    return 0;
}

#define WAND_ACTIVATE_DATA_CALL_TRIES 1
#define WAND_SET_UP_NETWORK_TRIES 2
static void prv_activate_data_call(void)
{
    int tries = 0;
    ril_data_call_response_t dataCallRsp;


    while (tries < WAND_ACTIVATE_DATA_CALL_TRIES) {
        int attach;
        if ((attach = ril_get_ps_attach()) < 0) {
            goto modem_down;
        }
        if (!attach) {
            sleep(1);
            tries++;
            continue;
        }

        int err = ril_activate_data_call(&dataCallRsp);
        if (err == RIL_ERR_NONFATAL) {
            sleep(1);
            tries++;
            continue;
        } else if (err == RIL_ERR_FATAL) {
            goto modem_down;
        }

        int netTries = 0;
        while (netTries < WAND_SET_UP_NETWORK_TRIES) {
            if (prv_set_up_network(&dataCallRsp) == 0) {
                sNetworkSetUp = 1;
                if (netwatch_init(NETIF_NAME(WAN_INTERFACE_0), prv_on_network_down, NULL) == 0) {
                    sNetWatchStarted = 1;
                    /* everything is set up */
                    prv_handle_wand_event(WAND_EVENT_DATA_CALL_UP);
                    return;
                } else {
                    AFLOG_ERR("netwatch_init_failed");
                    prv_shut_down_network();
                }
            }
            sleep(1);
            netTries++;
        }

        AFLOG_ERR("prv_activate_data_call:fatal:Can't set up network");
        ril_deactivate_data_call();
        return;
    }
    prv_handle_wand_event(WAND_EVENT_DATA_CALL_DOWN);
    return;

modem_down:
    prv_handle_wand_event(WAND_EVENT_MODEM_LOCKED);
    return;
}

static void prv_deactivate_data_call(void)
{
    int tries = 0;

    if (sNetWatchStarted) {
        netwatch_shutdown();
        sNetWatchStarted = 0;
    }

    if (sNetworkSetUp) {
        prv_shut_down_network();
        sNetworkSetUp = 0;
    }

    while (tries < WAND_ACTIVATE_DATA_CALL_TRIES) {
        if (ril_deactivate_data_call() >= 0) {
            break;
        }
        sleep(1);
        tries++;
    }

    if (tries >= WAND_ACTIVATE_DATA_CALL_TRIES) {
        AFLOG_ERR("prv_deactivate_data_call:fatal::can't deactivate data call");
    }
}

static void prv_reactivate_data_call(void)
{
    prv_deactivate_data_call();
    prv_activate_data_call();
}

static void prv_cancel_retry(void)
{
    evtimer_del(sRetryEvent);
}

static void prv_set_retry_time(int secsUntilRetry)
{
    struct timeval tv;
    tv.tv_sec = secsUntilRetry;
    tv.tv_usec = 0;
    evtimer_add(sRetryEvent, &tv);
}

static wand_event_t prv_translate_ril_event(ril_event_t event)
{
    wand_event_t wandEvent;

    switch(event) {
        case RIL_EVENT_DATA_CALL_LOST :
            wandEvent = WAND_EVENT_DATA_CALL_LOST;
            break;
        default :
            AFLOG_ERR("bad ril event %d", event);
            wandEvent = WAND_EVENT_BAD_RIL_EVENT;
            break;
    }
    AFLOG_DEBUG2("prv_translate_ril_event:tr_event:rilEvent=%d,wandEvent=%d", event, wandEvent);
    return wandEvent;
}

static void prv_on_ril_event(ril_event_t event, void *context)
{
    wand_event_t wandEvent = prv_translate_ril_event(event);
    prv_handle_wand_event(wandEvent);
}

static void prv_on_retry_event(evutil_socket_t fd, short what, void *arg)
{
    prv_handle_wand_event(WAND_EVENT_RETRY);
}

static void prv_on_idle_event(evutil_socket_t fd, short what, void *arg)
{
    /* this is a persistent event that keeps the event loop running */
    struct timeval tv = { WAND_IDLE_TIME, 0 };
    evtimer_add(sIdleEvent, &tv);
}

/* Code running in worker thread */

#define WANCONTROL "/usr/bin/wancontrol "
#define WANCONTROL_ON    WANCONTROL "on"
#define WANCONTROL_OFF   WANCONTROL "off"

static int prv_modem_power(char *command)
{
    int res = af_util_system(command);
    if (res != 0) {
        AFLOG_ERR("failed to power %s modem", command);
        return res;
    }
    return 0;
}

static int prv_modem_off(void)
{
    if (sRilStarted) {
        ril_shutdown();
        sRilStarted = 0;
    }

    /* shut down the network just in case */
    prv_shut_down_network();

    int result = prv_modem_power(WANCONTROL_OFF);
    if (result != 0) {
        AFLOG_ERR("wanoff:result=%d:can't turn WAN off", result);
        prv_handle_wand_event(WAND_EVENT_MODEM_UP);
        return -1;
    }

    prv_handle_wand_event(WAND_EVENT_MODEM_DOWN);
    return 0;
}

#define NO_WAN 254
#define WAN_POWER_ON_TRIES 4
static int prv_modem_on(void)
{
    int result;
    int tries = 0;

    while (tries++ < WAN_POWER_ON_TRIES) {
        result = prv_modem_power(WANCONTROL_ON);
        if (result != 0) {
            if (result == NO_WAN) {
                prv_handle_wand_event(WAND_EVENT_NO_MODEM);
                return -1;
            }
            continue;
        }


        /* initialize the RIL with the APN information */
        if (ril_init(sWandBase, prv_on_ril_event, NULL) < 0) {
            prv_modem_power(WANCONTROL_OFF);
            continue;
        }
        sRilStarted = 1;

        if (!sDataCallReqSetUp) {
            char iccid[24];

            /* get the iccid. This is pedantic and overkill */
            ril_wan_status_t *wStatus = ril_lock_wan_status();
            memcpy(iccid, wStatus->iccid, sizeof(wStatus->iccid));
            ril_unlock_wan_status();

            /* get the proper APN for the modem */
            if (prv_get_apn_info(iccid, &sDataCallReq) < 0) {
                AFLOG_ERR("modem_on_get_apn_info:errno=%d", errno);
                prv_modem_off();
                /* TODO this should be fatal */
                continue;
            }

            sDataCallReqSetUp = 1;
        }

        if (ril_select_network(&sDataCallReq) < 0) {
            AFLOG_ERR("modem_on_select_network:errno=%d", errno);
            prv_modem_power(WANCONTROL_OFF);
            continue;
        }

        prv_handle_wand_event(WAND_EVENT_MODEM_UP);
        return 0;
    }

    prv_handle_wand_event(WAND_EVENT_MODEM_DOWN);
    /* TODO this should be fatal */
    return -1;
}

#define CHECK_IN_COUNT_INTERVAL 360 // One hour for a ten second interval

static int sAttached = 0;
static int sCheckInCount = 0;

static int prv_check_signal(void)
{

    int attached = ril_get_ps_attach();
    if (attached < 0) {
        prv_handle_wand_event(WAND_EVENT_MODEM_LOCKED);
        return -1;
    }
    if (sAttached == 1 && attached == 0) {
        prv_handle_wand_event(WAND_EVENT_PS_ATTACH_LOST);
    }
    sAttached = attached;

    sCheckInCount++;
    if (sCheckInCount >= CHECK_IN_COUNT_INTERVAL) {
        AFLOG_INFO("worker_thread_check_in::");
        sCheckInCount = 0;
    }

    return 0;
}

/* worker thread code */
static void prv_dispatch_wand_command(wand_command_t cmd)
{
    switch (cmd) {

        case WAND_COMMAND_MODEM_ON :
            prv_modem_on();
            break;
        case WAND_COMMAND_MODEM_OFF :
            prv_modem_off();
            break;
        case WAND_COMMAND_ACTIVATE_DATA_CALL :
            prv_activate_data_call();
            break;
        case WAND_COMMAND_REACTIVATE_DATA_CALL :
            prv_reactivate_data_call();
            break;
        default :
            AFLOG_ERR("w_command:cmd=%d:unrecognized command", cmd);
            break;
    }
}

static int prv_send_wand_command(wand_command_t cmd)
{
    AFLOG_DEBUG2("prv_send_wand_command:command:cmd=%s", s_wand_command_names[cmd]);
    AFLOG_DEBUG3("locking cmd mutex");
    pthread_mutex_lock(&sCmdMutex);
    AFLOG_DEBUG3("locked cmd mutex");

    sCmdPending = cmd;
    pthread_cond_signal(&sCmdCond);

    pthread_mutex_unlock(&sCmdMutex);
    AFLOG_DEBUG3("unlocked cmd mutex");
    return 0;
}

static void *prv_worker_loop(void *arg)
{
    sCmdPending = WAND_COMMAND_MODEM_OFF;

    while (1) {
        wand_command_t cmd;
        struct timespec ts;
        wand_state_t state;

        pthread_mutex_lock(&sCmdMutex);

        sCmdExecuting = 0;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += WAND_MODEM_CHECK_TIME;
        while (sCmdPending == WAND_COMMAND_NONE) {
            if (pthread_cond_timedwait(&sCmdCond, &sCmdMutex, &ts) == ETIMEDOUT && sCmdPending == WAND_COMMAND_NONE) {
                sCmdPending = WAND_COMMAND_CHECK;
            }
        }

        cmd = sCmdPending;
        state = sWandState;
        sCmdPending = WAND_COMMAND_NONE;
        sCmdExecuting = 1;
        pthread_mutex_unlock(&sCmdMutex);

        if (cmd != WAND_COMMAND_CHECK) {
            prv_dispatch_wand_command(cmd);
        } else if (state == WAND_STATE_WAITING_FOR_DATA || state == WAND_STATE_DATA) {
            AFLOG_DEBUG3("prv_worker_loop:checking signal");
            prv_check_signal();
        }
    }
    return NULL;
}

static void prv_handle_wand_event(wand_event_t wandEvent) {
    AFLOG_DEBUG3("locking state mutex");
    pthread_mutex_lock(&sWandStateMutex);
    wand_state_t oldState = sWandState;
    AFLOG_DEBUG3("locked state mutex");
    switch (sWandState) {
        case WAND_STATE_OFF :
            AFLOG_INFO("WAN is off because no modem is found");
            break;

        case WAND_STATE_WAITING_FOR_DOWN :
            switch (wandEvent) {
                case WAND_EVENT_MODEM_DOWN :
                    sWandState = WAND_STATE_WAITING_FOR_UP;
                    prv_send_wand_command(WAND_COMMAND_MODEM_ON);
                    break;
                case WAND_EVENT_MODEM_UP :
                    prv_set_retry_time(WAND_RETRY_TIME_MODEM_OFF);
                    break;
                case WAND_EVENT_RETRY :
                    prv_send_wand_command(WAND_COMMAND_MODEM_OFF);
                    break;
                default :
                    AFLOG_ERR("w_event:event=%s,state=%s:unhandled wan event", s_wand_event_names[wandEvent], s_wand_state_names[oldState]);
                    break;
            }
            break;

        case WAND_STATE_WAITING_FOR_UP :
            switch (wandEvent) {
                case WAND_EVENT_MODEM_UP :
                    sWandState = WAND_STATE_WAITING_FOR_DATA;
                    sNumPsFailures = 0;
                    sDataCallLostWhileActivating = 0;
                    prv_send_wand_command(WAND_COMMAND_ACTIVATE_DATA_CALL);
                    break;
                case WAND_EVENT_MODEM_DOWN :
                    prv_set_retry_time(WAND_RETRY_TIME_MODEM_ON);
                    break;
                case WAND_EVENT_RETRY :
                    prv_send_wand_command(WAND_COMMAND_MODEM_ON);
                    break;
                case WAND_EVENT_NO_MODEM :
                    sWandState = WAND_STATE_OFF;
                    break;
                default :
                    AFLOG_ERR("w_event:event=%s,state=%s:unhandled wan event", s_wand_event_names[wandEvent], s_wand_state_names[oldState]);
                    break;
            }
            break;

        case WAND_STATE_WAITING_FOR_DATA :
            switch (wandEvent) {
                case WAND_EVENT_DATA_CALL_UP :
                    if (sDataCallLostWhileActivating) {
                        sDataCallLostWhileActivating = 0;
                        prv_set_retry_time(WAND_RETRY_TIME_DATA_CALL);
                    } else {
                        sNumPsFailures = 0;
                        sWandState = WAND_STATE_DATA;
                        AFLOG_INFO("data:numPsFailures=%d:connection established",sNumPsFailures);
                    }
                    break;
                case WAND_EVENT_DATA_CALL_DOWN :
                    sNumPsFailures++;
                    if (sNumPsFailures >= WAND_NUM_PS_FAILURES_UNTIL_REBOOT) {
                        AFLOG_WARNING("ps_attach:numPsFailures=%d:failed to attach; rebooting modem", sNumPsFailures);
                        sWandState = WAND_STATE_WAITING_FOR_DOWN;
                        sNumPsFailures = 0;
                        prv_send_wand_command(WAND_COMMAND_MODEM_OFF);
                    } else {
                        prv_set_retry_time(WAND_RETRY_TIME_DATA_CALL);
                    }
                    break;
                case WAND_EVENT_MODEM_LOCKED :
                    sWandState = WAND_STATE_WAITING_FOR_DOWN;
                    prv_cancel_retry();
                    prv_send_wand_command(WAND_COMMAND_MODEM_OFF);
                    break;
                case WAND_EVENT_DATA_CALL_LOST :
                    /* HUB-344 set a flag to indicate that the data call will not work */
                    sDataCallLostWhileActivating = 1;
                    break;
                case WAND_EVENT_RETRY :
                    prv_send_wand_command(WAND_COMMAND_ACTIVATE_DATA_CALL);
                    break;
                default :
                    AFLOG_ERR("w_event:event=%s,state=%s:unhandled wan event", s_wand_event_names[wandEvent], s_wand_state_names[oldState]);
                    break;
            }
            break;

        case WAND_STATE_DATA :
            switch (wandEvent) {
                case WAND_EVENT_MODEM_LOCKED :
                    sWandState = WAND_STATE_WAITING_FOR_DOWN;
                    prv_send_wand_command(WAND_COMMAND_MODEM_OFF);
                    break;
                case WAND_EVENT_PS_ATTACH_LOST :
                case WAND_EVENT_DATA_CALL_LOST :
                    sWandState = WAND_STATE_WAITING_FOR_DATA;
                    prv_send_wand_command(WAND_COMMAND_REACTIVATE_DATA_CALL);
                    break;
                default :
                    AFLOG_ERR("w_event:event=%s,state=%s:unhandled wan event", s_wand_event_names[wandEvent], s_wand_state_names[oldState]);
                    break;
            }
            break;

        default :
            break;
    }
    AFLOG_DEBUG1("prv_handle_wand_event:event:event=%s,oldState=%s,state=%s",
                s_wand_event_names[wandEvent], s_wand_state_names[oldState], s_wand_state_names[sWandState]);
    pthread_mutex_unlock(&sWandStateMutex);
    AFLOG_DEBUG3("unlocked state mutex");
}

int evthread_use_pthreads(void);

void wand_shutdown(void)
{
    prv_modem_off();

    if (sIpcInitialized) {
        wan_ipc_shutdown();
        sIpcInitialized = 0;
    }

    if (sCmdCondCreated) {
        pthread_cond_destroy(&sCmdCond);
        sCmdCondCreated = 0;
    }

    if (sCmdCondAttrCreated) {
        pthread_condattr_destroy(&sCmdCondAttr);
        sCmdCondAttrCreated = 0;
    }

    if (sCmdThreadCreated) {
        void *result;
        pthread_cancel(sCmdThread);
        pthread_join(sCmdThread, &result);
        sCmdThreadCreated = 0;
    }

    if (sIdleEvent) {
        event_del(sIdleEvent);
        event_free(sIdleEvent);
        sIdleEvent = NULL;
    }

    if (sRetryEvent) {
        event_del(sRetryEvent);
        event_free(sRetryEvent);
        sRetryEvent = NULL;
    }

    if (sWandBase) {
        event_base_free(sWandBase);
        sWandBase = NULL;
    }

    closelog();
}

static int wand_init(void)
{
    /* get network interface names */
    if (NETIF_NAMES_GET() < 0) {
        return -1;
    }

    AFLOG_INFO("wan_network_interface:name=%s", NETIF_NAME(WAN_INTERFACE_0));

    /* allow libevent2 to use pthreads */
    evthread_use_pthreads();

    sWandBase = event_base_new();
    if (!sWandBase) {
        return -1;
    }

    sRetryEvent = event_new(sWandBase, -1, EV_TIMEOUT, prv_on_retry_event, NULL);
    if (sRetryEvent == NULL) {
        return -1;
    }

    sIdleEvent = event_new(sWandBase, -1, EV_TIMEOUT, prv_on_idle_event, NULL);
    if (sIdleEvent == NULL) {
        return -1;
    }

    /* add the idle timer */
    struct timeval tv = { WAND_IDLE_TIME, 0 };
    evtimer_add(sIdleEvent, &tv);

    if (pthread_create(&sCmdThread, NULL, prv_worker_loop, NULL) != 0) {
        AFLOG_ERR("ril_init::failed to create pthread::errno=%d", errno);
        return -1;
    }
    sCmdThreadCreated = 1;

    if (pthread_condattr_init(&sCmdCondAttr) < 0) {
        AFLOG_ERR("ril_init:pthread_condattr_init:errno=%d", errno);
        return -1;
    }
    sCmdCondAttrCreated = 1;

    pthread_condattr_setclock(&sCmdCondAttr, CLOCK_MONOTONIC);

    if (pthread_cond_init(&sCmdCond, &sCmdCondAttr) < 0) {
        AFLOG_ERR("ril_init:pthread_cond_init:errno=%d", errno);
        return -1;
    }
    sCmdCondCreated = 1;

    if (wan_ipc_init(sWandBase) < 0) {
        return -1;
    }
    sIpcInitialized = 1;

    return 0;
}

#ifdef BUILD_TARGET_DEBUG
uint32_t g_debugLevel = LOG_DEBUG3;
#else
uint32_t g_debugLevel = LOG_DEBUG1;
#endif

extern const char REVISION[];
extern const char BUILD_DATE[];

int main()
{
    openlog("wand", LOG_PID, LOG_USER);

    AFLOG_INFO("start_wand:revision=%s,build_date=%s", REVISION, BUILD_DATE);

    if (wand_init() == 0) {
        sWandState = WAND_STATE_WAITING_FOR_DOWN;

        /* This is a hack. "Retry" to start state machine */
        prv_set_retry_time(1);

        event_base_dispatch(sWandBase);
    }

    wand_shutdown();

    return 1; /* This daemon has no clean exit condition */
}

/* get the wand evbase
 */
struct event_base *wand_get_evbase()
{
    return (sWandBase);
}

char *wan_apn(void)
{
    return sDataCallReq.apn;
}
