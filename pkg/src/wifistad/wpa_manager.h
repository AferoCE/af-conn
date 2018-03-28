#ifndef _WPA_MANAGER_H_
#define _WPA_MANAGER_H_

#include <event.h>

#define ETH_ALEN 6

// error code
#define WPA_CONN_RESULT_INIT                (0)
#define WPA_CONN_RESULT_NO_ID               (-1)
#define	WPA_CONN_RESULT_ASS_REJECT          (-2)
#define	WPA_CONN_RESULT_TEMP_DISABLED       (-3)
#define WPA_CONN_RESULT_HANDSHAKE_FAILED    (-4)
#define WPA_CONN_RESULT_INVALID_SSID        (-5)
#define WPA_CONN_RESULT_SET_PSK_FAILED      (-6)
#define WPA_CONN_RESULT_END                 (-99)

#define WIFISTA_SSID_LEN                32
#define WIFISTA_BSSID_LEN               18


// WPA event IDs
#undef _SUB
#define _SUB(_x) WPA_EVENT_ID_##_x

//  WPA_EVENT_ID ENUM
#define WPA_EVENT_IDS \
    _SUB(READY), \
    _SUB(SCAN_STARTED), \
    _SUB(CONNECTING), \
    _SUB(CONNECTED), \
    _SUB(DISCONNECTED), \
    _SUB(STATUS), \
    _SUB(SCAN_RESULTS), \
    _SUB(WIFI_SCAN_REQUESTED), \
    _SUB(WIFI_CREDENTIALS),  \
    _SUB(TERMINATED), \
    _SUB(CFG_CHECK),  \
    _SUB(REESTABLISHED)    // TODO - trigger must be from connmgr

typedef enum {
    WPA_EVENT_IDS,
    WPA_EVENT_ID_MAX
}wpa_event_id_e;

typedef struct wpa_event_s {
    wpa_event_id_e id;
    void *result;
} wpa_event_t;


typedef void (*wpa_manager_asyc_cb_t)(void *param, void *result);
typedef void (*wpa_manager_wpa_event_callback_t)(wpa_event_t *result);


/*
 * wifi setup -- based on the device attribute registry
 *
 * http://wiki.afero.io/display/FIR/Device+Attribute+Registry
 */
typedef enum {
    // WifiSetupState: not connected, no pending command
    // WifiSteadyState, wifi not connected
    WIFI_STATE_NOTCONNECTED = 0,

    // WifiSetupState: connection attempt in progress
    // WifiSteadyState: not used, or ?
    WIFI_STATE_PENDING = 1,

    // WifiSetupState: You're a star! All done.
    // WifiSteadyState: All systems nominal
    WIFI_STATE_CONNECTED = 2,

    // catchy all state
    WIFI_STATE_UNKNOWN = 3,

    // WifiSetupState: Association failed for the current setup task. Tell user can't connect.
    // WifiSteadyState: Association failed for the currently-saved SSID. Alert user.
    WIFI_STATE_ASSOCATIONFAILED = 4,

    // WifiSetupState: Handshake failed for the current setup task. Tell user to try new password.
    // WifiSteadyState: Handshake failed for the currently-saved SSID. Alert user.
    WIFI_STATE_HANDSHAKEFAILED = 5,

    // WifiSetupState: Could not see Afero service after successfully connecting to the base station. Check internet connection (fail whale)
    // WifiSteadyState: Could not see Afero service after successfully connecting to the base station. Alert user.
    WIFI_STATE_ECHOFAILED = 6,

    // SSID not found, for scenario that scan sees the AP, but connect fail to find it
    WIFI_STATE_SSID_NOT_FOUND = 7,
} wifi_state_e;

typedef wifi_state_e  wifi_setup_state_e;


typedef enum {
    INIT_NONE = 0,
    AUTO_CONNECT,
    USER_REQUEST
} wifi_setup_mode_e;


// TODO -- may need to be mutex protected.
typedef struct {
    // who initiates the wifi setup
    wifi_setup_mode_e       who_init_setup;

    // The wifi_state_e during user wifi configuration setup
    // if (who_inti_setup == USER_REQEUSTED) =>setup_state
    // otherwise,                            => steady_state
    uint8_t                 setup_state;

    wpa_event_id_e          setup_event;

    // this represents the network id or error code
    int32_t                 network_id;

    // the network id currently connected to before we try
    // to connect to "this" AP.
    int32_t                 prev_network_id;

    // blob, depends on the event_id
    void                    *data_p;

    // attrd response info
    uint32_t                attributeId;
    uint16_t                getId;
} wpa_wifi_setup_t;;


/* Macro to reset the wifi setup data structure */
#define RESET_WIFI_SETUP(m,cache_state)                         \
do {                                                            \
    (m)->wifi_setup.who_init_setup = INIT_NONE;                 \
    if (!cache_state) (m)->wifi_setup.setup_state = WIFI_STATE_NOTCONNECTED; \
    (m)->wifi_setup.setup_event = 0;                            \
    (m)->wifi_setup.network_id = -1;                            \
    (m)->wifi_setup.data_p = NULL;                              \
    (m)->wifi_setup.prev_network_id = -1;                       \
    (m)->wifi_setup.attributeId = 0;                            \
    (m)->wifi_setup.getId  = 0;                                 \
} while (0)

#define UPDATE_WIFI_SETUP_STATE(m, s, id)           \
do {                                                \
    (m)->wifi_setup.setup_state = (s);              \
    (m)->wifi_steady_state = (s);                   \
    (m)->wifi_setup.network_id = (id);              \
} while (0)

#define WIFI_SETUP_IS_USER_REQUESTED(m)                         \
    ( (m)->wifi_setup.who_init_setup == USER_REQUEST)           \

#define WIFI_SETUP_SCAN_REQUEST(m)                              \
do {                                                            \
    (m)->wifi_setup.who_init_setup = USER_REQUEST;              \
    (m)->wifi_setup.setup_state = WIFI_STATE_NOTCONNECTED;      \
    (m)->wifi_setup.setup_event = WPA_EVENT_ID_WIFI_SCAN_REQUESTED; \
    (m)->wifi_setup.network_id = WPA_CONN_RESULT_INIT;              \
    (m)->wifi_setup.data_p = NULL;                                  \
    (m)->wifi_setup.prev_network_id = WPA_CONN_RESULT_INIT;         \
} while (0)

#define WIFI_SETUP_CONNECT_AP(m, cred, id)                          \
do {                                                                \
    (m)->wifi_setup.who_init_setup = USER_REQUEST;                  \
    (m)->wifi_setup.setup_state = WIFI_STATE_NOTCONNECTED;          \
    (m)->wifi_setup.setup_event = WPA_EVENT_ID_WIFI_CREDENTIALS;    \
    (m)->wifi_setup.network_id = WPA_CONN_RESULT_INIT;              \
    (m)->wifi_setup.data_p = (void *)(cred);                        \
    (m)->wifi_setup.prev_network_id = (id);                         \
} while (0)

#define WIFI_SETUP_ATTR_CTX(m, attrId, getId)           \
do {                                                    \
    (m)->wifi_setup.attributeId = (attrId);             \
    (m)->wifi_setup.getId = (getId);                    \
} while (0)


/* > status
 * bssid=ec:08:6b:24:b4:6f
 * freq=2462
 * ssid=zz_[AFD]_TPL-AC1750_2
 * id=1
 * mode=station
 * pairwise_cipher=CCMP
 * group_cipher=CCMP
 * key_mgmt=WPA2-PSK
 * wpa_state=COMPLETED
 * ip_address=192.168.201.105
 * p2p_device_address=90:6f:18:00:00:a1    // our mac
 * address=90:6f:18:00:00:a1
 * uuid=9d983a67-e381-54f2-bad7-d77f09b35628
 */
#define WPA_STATUS_STR_LEN       32
#define UUID_STR_LEN             36

typedef struct {
    uint8_t      associated;  // flag to indicate this dev is associated?

    char         bssid[18];
    char         ssid[WIFISTA_SSID_LEN + 1];
    uint32_t     freq;
    int32_t      id;  // network id
    char         mode[WPA_STATUS_STR_LEN];
    char         pairwise_cipher[WPA_STATUS_STR_LEN];
    char         group_cipher[WPA_STATUS_STR_LEN];
    char         key_mgmt[WPA_STATUS_STR_LEN];
    char         wpa_state[WPA_STATUS_STR_LEN];
    char         ip_address[18];
    char         p2p_device_address[18];
    char         address[18];
    char         uuid[UUID_STR_LEN+1];
} wpa_sta_assoc_t;


#undef _SUB
#define _SUB(_x) WPA_CMD_##_x

#define WPA_CMDS \
    _SUB(STATUS), \
    _SUB(SCAN), \
    _SUB(SCAN_RESULTS), \
    _SUB(SELECT_NETWORK), \
    _SUB(ENABLE_NETWORK), \
    _SUB(DISABLE_NETWORK), \
    _SUB(ADD_NETWORK), \
    _SUB(REMOVE_NETWORK), \
    _SUB(SET_NETWORK), \
    _SUB(GET_NETWORK), \
    _SUB(LIST_NETWORKS), \
    _SUB(DISCONNECT), \
    _SUB(RECONNECT),    \
    _SUB(SIGNAL_POLL), \
    _SUB(PING)

typedef enum {
    WPA_CMDS,
    WPA_NUM_EVENTS
} wpa_cmd_t;

#undef _SUB
#define _SUB(_x) #_x


#undef _SUB
#define _SUB(_x) WPA_OP_##_x

#define WPA_OPS \
    _SUB(CONFIGURE_NETWORK), \
    _SUB(STATUS), \
    _SUB(SCAN), \
    _SUB(SCAN_RESULTS), \
    _SUB(CONNECT), \
    _SUB(RECONNECT), \
    _SUB(DISCONNECT), \
    _SUB(SIGNAL_POLL), \
    _SUB(REMOVE_NETWORK), \
    _SUB(LIST_NETWORKS)

typedef enum {
    WPA_OPS,
    WPA_NUM_OPS
} wpa_op_t;

#undef _SUB
#define _SUB(_x) #_x

extern char *s_wpa_op_names[];

typedef struct {
    wpa_cmd_t id;
    char *cmd;
} wpa_async_req_t;

struct wpa_op_desc_s;
typedef void * (*wpa_op_func_t)(struct wpa_op_desc_s *op_desc);

typedef struct {
    char    ssid[64];
    uint8_t ssid_len;
    char    psk[64];
    uint8_t psk_len;
    char    bssid[17]; /* colon separated string */
    int     priority;
} configure_network_params_t;

typedef struct {
    int     network_id;
} connect_params_t;

typedef struct wpa_op_desc_s {
    wpa_op_t        op;
    uint8_t         pending;
    wpa_manager_asyc_cb_t cb;
    void            *cb_param;
    wpa_op_func_t   func;
    union {
        configure_network_params_t  configure_network_params;
        connect_params_t            connect_params;
    } func_params;
} wpa_op_desc_t;

typedef struct wpa_manager {
    uint8_t   started;
    struct event_base *evbase;
    struct event *tm_event;
    struct event *wpa_event;
    char *ctrl_iface_name;
    struct wpa_ctrl *ctrl_conn;
    struct wpa_ctrl *mon_conn;
    pthread_t op_thread;
    pthread_condattr_t op_cond_attr;
    pthread_cond_t op_cond;
    pthread_mutex_t op_cond_mutex;
    uint8_t op_thread_created;
    uint8_t op_cond_attr_created;
    uint8_t op_cond_created;
    uint8_t op_cond_mutex_created;
    wpa_op_desc_t current_op;

    struct event *rpt_rssi_event;

    /* ----------------------------- */
    /* WIFI connection states/info   */
    /* ----------------------------- */
    // wifi setup info
    wpa_wifi_setup_t   wifi_setup;

    // wifi steady state info (of type wifi_state_e), during
    // reconnect, bootup
    uint8_t             wifi_steady_state;

    // wpa station association info
    wpa_sta_assoc_t    assoc_info;
} wpa_manager_t;

typedef struct wpa_client {
    wpa_manager_wpa_event_callback_t wpa_event_cb;
} wpa_client_t;

typedef enum {
    NETWORK_LOOKUP_KEY_TYPE_SSID,
    NETWORK_LOOKUP_KEY_TYPE_BSSID,
} network_lookup_key_type_e;


/***
 * APIs
 */
int wpa_manager_init(struct event_base *evbase, wpa_manager_wpa_event_callback_t wpa_event_cb, void *wpa_event_cb_param);
int wpa_manager_destroy(void);
int wpa_manager_status_async(wpa_manager_asyc_cb_t cb, void *param);
int wpa_manager_scan_async(wpa_manager_asyc_cb_t cb, void *param);
int wpa_manager_connect_async(wpa_manager_asyc_cb_t cb, void *param, int network_id);
int wpa_manager_reconnect_async(wpa_manager_asyc_cb_t cb, void *param);
int wpa_manager_disconnect_async(wpa_manager_asyc_cb_t cb, void *param);
int wpa_manager_remove_network_async(wpa_manager_asyc_cb_t cb, void *param, int network_id);

/* add new net based on ssid to supp config if it doesn't already exist. otherwise, update. */
int wpa_manager_configure_ssid_async(wpa_manager_asyc_cb_t cb, void *param, char *ssid, char *psk, int priority);

/* add new net based on bssid to supp config if it doesn't already exist. otherwise, update. */
int wpa_manager_configure_bssid_async(wpa_manager_asyc_cb_t cb, void *param, char *ssid, char *psk, char *bssid, int priority);


/* retrieve the wpa_manager control block */
extern wpa_manager_t *wifista_get_wpa_mgr();
extern void wifista_wpa_post_event(wpa_event_id_e id, void *result);
extern int wpa_get_conn_network_rssi ();
extern void wpa_periodic_check(evutil_socket_t fd, short what, void *arg);
extern void wpa_manager_dump();


// reply to sender
extern void wifista_setup_send_rsp(wpa_wifi_setup_t  *wifi_p);
extern void wifista_report_rssi_tmout_handler (evutil_socket_t fd, short events, void *arg);
extern void wifista_set_wifi_steady_state(uint8_t    steady_state);

#endif  // _WPA_MANAGER_H_
