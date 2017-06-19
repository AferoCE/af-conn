#ifndef WAN_API_HEADER
#define WAN_API_HEADER
//#include "cm_common.h"
#include <stdint.h>
#include <netinet/in.h>
#include "cm_constant.h"

typedef enum {
    WAN_CMD_BASE = 0x0,

    /* 
        paramemter 
            [wan_connection_setup_param]: data connection setup parameter 
        response
             success indicates request submitted, caller should listen for
             notification to find out when it actually occurs
    */ 
    WAN_CMD_START_CONNECTION,


    /* 
        paramemter 
            [wan_connection_token]: token that specifies connection
        response
             success indicates request submitted, caller should listen for
             notification to find out when it actually occurs
    */ 
    WAN_CMD_STOP_CONNECTION,

    /* 
        paramemter 
            [uint8_t]: APN type to query

        response
            [wan_network_if_info]: interface information for the requested apn
                                   type. failure indicates requested APN is not 
                                   connected.
    */ 
    WAN_CMD_GET_CONNECTION_STATE,

    /* paramemter 
        

    */
    WAN_CMD_SET_RADIO_POWER,
    WAN_CMD_GET_NETWORK_OPERATOR,
    WAN_CMD_GET_SIM_OPERATOR,

    /* 
        paramemter - NONE
        response
            [int]:  1 = supported, 0 = not supported
    */ 
    WAN_CMD_IS_SUPPORTED,

    /* notification */
    WAN_CMD_CONNECTION_CHANGE_NOTIFY,
    WAN_CMD_POWER_CHANGE_NOTIFY,

    WAN_CMD_MAX
} local_cmd;

typedef enum {
    WAN_REQUEST_SUCCESS = 0,
    WAN_REQUEST_ERR_NO_EFFECT,
    WAN_REQUEST_ERR_INTERNAL,
    WAN_REQUEST_ERR_INVALID_PARAM,
    WAN_REQUEST_ERR_MAX
} wan_request_err_code;

typedef enum {
    APN_TYPE_DEFAULT,
    APN_TYPE_IMS,
    APN_TYPE_MMS,
    APN_TYPE_OEM_START = 100,
    APN_TYPE_OEM_END = 200,
    APN_TYPE_MAX
} wan_apn_types;

typedef cm_token wan_token;

//int wan_set_power(cm_link_power_mode mode);

typedef struct {
    uint8_t apn;
    wan_token t;
} wan_connection_setup_param;

typedef enum {
    WAN_CONNECTION_CONNECTED = 0,
    WAN_CONNECTION_DISCONNECTED,
    WAN_CONNECTION_SCORE_UPDATE,
    WAN_CONNECTION_CONFIG_UPDATE,
    WAN_CONNECTION_EVENT_MAX
} wan_connection_event;

/* ip/data */
typedef struct {
    uint8_t valid;
    struct in6_addr addr;
} ipv6_addr;

typedef struct {
    uint8_t valid;
    struct in_addr addr;
} ipv4_addr;

typedef struct {
    ipv4_addr ip;
    ipv4_addr gw;
    ipv4_addr dns_main;
    ipv4_addr dns_sec;
} ip_info_v4;

typedef struct {
    ipv6_addr ip;
    ipv6_addr gw;
    ipv6_addr dns_main;
    ipv6_addr dns_sec;
} ip_info_v6;

#define WAN_NETWORK_IF_NAME_MAX 32
typedef struct {
    uint8_t     type; /* ip type */
    char        name[WAN_NETWORK_IF_NAME_MAX];
    ip_info_v4  v4;
    ip_info_v6  v6;
} cm_interface_info;

typedef struct {
    uint8_t           status;
    uint8_t           active;
    uint8_t           cid;
    cm_interface_info interface;
} wan_network_if_info;

typedef struct {
    uint8_t  event;
    uint8_t  apn;
} wan_connection_info_hdr;

typedef struct {
    wan_connection_info_hdr hdr;
    uint16_t                score;
    wan_network_if_info     interface;
} wan_connection_info;

typedef void (*wan_cb) (int cmd, void *data, int datalen);

int wan_init(void *ipc, wan_cb cb);
int wan_request(int cmd, void *in, int inlen, void *out, int* outlen);

#endif