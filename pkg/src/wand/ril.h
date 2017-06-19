/*
 * ril.h -- Radio Interface Layer definitions
 *
 * Copyright (c) 2015-2016, Afero, Inc. All rights reserved.
 *
 * Kai Hu, Clif Liu, and Evan Jeng
 *
 * LTE only
 */

#ifndef __RIL_H__
#define __RIL_H__

#include <event2/event.h>

#define ALLEVENTS \
    EV(DATA_CALL_LOST)

#define EV(_x) RIL_EVENT_##_x

typedef enum {
    ALLEVENTS,
    RIL_EVENT_NUM_EVENTS
} ril_event_t;

#undef EV


#define RIL_ERR_NONE         0
#define RIL_ERR_NONFATAL    -1
#define RIL_ERR_FATAL       -2

#define PDN_AUTH_TYPE_LEN_MAX 1
#define PDN_PROTOCOL_LEN_MAX 6
#define PDN_APN_LEN_MAX 100
#define PDN_USER_LEN_MAX 64
#define PDN_PASSWORD_LEN_MAX 64

typedef struct {
    char auth_type[PDN_AUTH_TYPE_LEN_MAX + 1];
    char protocol[PDN_PROTOCOL_LEN_MAX + 1];
    char apn[PDN_APN_LEN_MAX + 1];
    char user[PDN_USER_LEN_MAX + 1];
    char password[PDN_PASSWORD_LEN_MAX + 1];
} ril_data_call_request_t;

#define IPV4_ADDR_SIZE 16 /* includes trailing 0 */
#define IPV6_ADDR_SIZE 40 /* includes trailing 0 */

typedef struct {
    int subnet_v4;
    int subnet_v6;
    char ip_v4[IPV4_ADDR_SIZE];
    char ip_v6[IPV6_ADDR_SIZE];
    char dns1_v4[IPV4_ADDR_SIZE];
    char dns2_v4[IPV4_ADDR_SIZE];
    char dns1_v6[IPV6_ADDR_SIZE];
    char dns2_v6[IPV6_ADDR_SIZE];
} ril_data_call_response_t;

typedef void (*ril_event_callback_t)(ril_event_t event, void *context);

int ril_init(struct event_base *base, ril_event_callback_t callback, void *context);
int ril_select_network(ril_data_call_request_t *dataCallReq);

char *ril_get_iccid(void);
char *ril_get_sim_status(void);

int ril_get_ps_attach(int *attachedP);

char *ril_get_camp_status(void);
char *ril_get_serving_status(void);
char *ril_get_neighbor_status(void);
uint8_t ril_get_bars(void);

/* These functions block and return 0 if they succeed */
int ril_activate_data_call(ril_data_call_response_t *dataCallRsp);
int ril_deactivate_data_call(void);

void ril_shutdown(void);

#endif // __RIL_H__
