#ifndef CM_CONSTANT_H
#define CM_CONSTANT_H

typedef enum cm_types {
    CONNECTION_CAPABILITY_DEFAULT = 0,
    CONNECTION_CAPABILITY_P2P,
    CONNECTION_CAPABILITY_SOFTAP,
    CONNECTION_CAPABILITY_MMS,
    CONNECTION_CAPABILITY_IMS,
    CONNECTION_CAPABILITY_WIFI_USER_DEFINED,
    CONNECTION_CAPABILITY_WWAN_USER_DEFINED,

    CONNECTION_CAPABILITY_MAX
} cm_connection_capabilities;

typedef enum {
    CONNECTION_LINK_WAN = 0,
    CONNECTION_LINK_WIFI,
    CONNECTION_LINK_BLUETOOTH,
    CONNECTION_LINK_ETHERNET,
    CONNECTION_LINK_MAX
} cm_connection_link_t;

typedef enum {
    CONNECTION_ATTR_ENABLE = 0,
    CONNECTION_ATTR_DEFAULT,
    CONNECTION_ATTR_MAX = 32
} cm_connection_attr_t;

typedef enum {
    CM_LINK_POWER_ON,
    CM_LINK_POWER_OFF,
    CM_LINK_POWER_LOW,
    CM_LINK_POWER_UNKNOWN,
    CM_LINK_POWER_MAX
} cm_link_power_mode;

typedef enum cm_states {
    CONNECTION_STATE_IDLE,
    CONNECTION_STATE_CONNECTING,
    CONNECTION_STATE_CONNECTED,
    CONNECTION_STATE_DISCONNECTING,
    CONNECTION_STATE_DISCONNECTED,
    CONNECTION_STATE_MAX
} cm_connection_state_t;

/* all connections are tracked with this token */
typedef uint16_t cm_token;

/* each radio subsystem can use this token to track connections internally
   where lower part is same as cm_token
         upper part is IPC client id
*/
typedef uint32_t radio_token;

#endif
