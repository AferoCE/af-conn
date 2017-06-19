#ifndef IPC_CLIENT_HEADER
#define IPC_CLIENT_HEADER

#include <pthread.h>
#include "connectivity_util.h"

#define PACKED(a) a __attribute__ ((__packed__))

/* Minimum len is when topic is NULL with data_len = 0 */
#define IPC_HEADER_MIN_LEN (sizeof(ipc_msg_packed) - sizeof(uint8_t *)) 

#define STRINGTIFY(str) #str
#define GEN_TOPIC_NAME(topic) STRINGTIFY(topic) ""

#define IPC_TOPIC_STR_WAN   "[WAN]"
#define IPC_TOPIC_STR_WIFI  "[WIFI]"
#define IPC_TOPIC_STR_CM    "[CONNECTION MANAGER]"
#define IPC_TOPIC_STR_EVENT "[EVENT]"

#define IPC_TOPIC_INIT(key) IPC_TOPIC_LOOKUP_INIT(key, GEN_TOPIC_NAME(key))
#define IPC_TOPIC_LOOKUP_INIT(key, value) {sizeof(value), key, value, NULL}

/* we use table for MOD operations, so prime numbers are better */
#define IPC_MAX_OUTSTANDING_REQ 13

typedef enum {
    IPC_MSG_REQ = 0,
    IPC_MSG_RSP,
    IPC_MSG_NOTIFICATION,
    IPC_MSG_CONTROL_REQ,
    IPC_MSG_CONTROL_RSP,
    IPC_MSG_TYPE_MAX
} ipc_msg_type;

typedef enum {
    IPC_CONTROL_QUERY_LINK = 0,
    IPC_CONTROL_MSG_MAX
} ipc_control_msg;

typedef enum {
    IPC_TOPIC_WAN = 0,
    IPC_TOPIC_WIFI,
    IPC_TOPIC_CM,
    IPC_TOPIC_EVENT,
    IPC_TOPIC_MAX
} ipc_topics;

typedef enum {
    IPC_LINK_TYPE_REQ = 0,
    IPC_LINK_TYPE_IND,
    IPC_LINK_TYPE_SURVEY,
    IPC_LINK_TYPE_MAX
} ipc_link_types;

typedef PACKED(struct) ipc_msg_struct {
    uint16_t data_len;
    uint16_t topic;
    uint8_t  type;
    uint16_t status;  /* only valid for rsp */
    uint16_t id;
    uint16_t seq_num;
    uint8_t  *data;
} ipc_msg_packed;

typedef void* ipc_ep;

typedef void* ipc_handle;

typedef void ipc_msg;

typedef void (*my_ev_io_cb)(struct ev_loop *loop, ev_io *watcher, int revents);

typedef int (*ipc_msg_cb)(ipc_msg *msg, void *rsp_data);

/* structure that holds all the information for sending an IPC
   message
*/
typedef struct ipc_msg_info_struct {
    uint8_t      type;
    uint16_t     id;
    uint16_t     data_len;
    uint16_t     seq_num;
    uint16_t     status;
    int16_t      wait;
    ipc_topics   topic; //TODO, remove
    void         *client; 
    uint8_t      *data;
    int (*cb)(ipc_msg *msg, void *rsp_data);
} ipc_msg_info;

typedef struct {
    uint8_t  req_enabled;
    uint8_t  event_enabled;
    uint8_t  version;
    uint16_t client_id;
} ipc_link_property;

typedef struct {
    uint8_t    async;
    uint16_t   seq_num;
    ipc_msg_cb cb;
} ipc_req_info;

/*
new world
*/
#define IPC_CLIENT_MAX_PENDING_REQ 10
typedef struct ipc_context_struct {
    /* book keeping */
    uint32_t        magic;
    uint8_t         buf[512];
    uint8_t         req_cnt;
    ipc_req_info    req[IPC_CLIENT_MAX_PENDING_REQ];
    uint16_t        seq_num;
    ipc_msg_info    cur_msg_info;
    struct ipc_service_info_struct *service_list;
    
    /* thread */
    pthread_t       thread;
    pthread_mutex_t mutex;
    pthread_cond_t  cond_rsp;
    pthread_cond_t  cond_ack;
    void            *mempool;

    /* libev */
    ev_async        ev_async_watcher;
    struct ev_loop  *ev_loop;
//ipc_channel_ctx_t channel[IPC_CLIENT_MAX_CHANNELS];
} ipc_context;

typedef struct ipc_service_client_struct {
    struct ipc_service_client_struct *next;
    struct ipc_service_info_struct   *service;
    ipc_msg_cb                       cb;
    ev_io                            watcher;
    ipc_link_property                property;
    ipc_topics                       topic;
    int                              fd_socket;
} ipc_service_client;

typedef struct ipc_service_info_struct {
   struct ipc_service_info_struct *next;
   ipc_service_client             *client_list;
   ipc_context                    *base;
   ipc_msg_cb                     cb;
   ipc_topics                     topic;
   ipc_link_property              property;
   uint8_t                        client_cnt; 
   uint8_t                        flag_provider;
} ipc_service_info;

static inline void ipc_client_enable_req_channel(ipc_service_client *client, ipc_msg_cb cb)
{
    client->property.req_enabled = 1;
}

static inline void ipc_client_enable_event_channel(ipc_service_client *client, ipc_msg_cb cb)
{
    client->property.event_enabled = 1;
}

static inline void ipc_client_set_version(ipc_service_client *client, int version)
{
    client->property.version = version;
}

static inline int ipc_msg_get_seq_num(ipc_msg *msg)
{
    return ((ipc_msg_info *)msg)->seq_num;
}

static inline int ipc_msg_get_payload_len(ipc_msg *msg)
{
    return ((ipc_msg_info *)msg)->data_len;
}

static inline uint8_t ipc_msg_get_topic(ipc_msg *msg)
{
    return ((ipc_msg_info *)msg)->topic;
}

static inline uint16_t ipc_msg_get_id(ipc_msg *msg)
{
    return ((ipc_msg_info *)msg)->id;
}

static inline int ipc_msg_get_status(ipc_msg *msg)
{
    return ((ipc_msg_info *)msg)->status;
}

static inline uint8_t* ipc_msg_get_payload(ipc_msg *msg)
{
    return ((ipc_msg_info *)msg)->data;
}

static inline int ipc_msg_get_client_id(ipc_msg *msg)
{
    ipc_service_client client;
    client = (ipc_service_client *)(((ipc_msg_info *)msg)->client);
    return client != NULL ? client->property.client_id : 0;
}

static inline void ipc_msg_set_cb(ipc_msg *msg, ipc_msg_cb cb)
{
    ipc_msg_info *info = (ipc_msg_info *)msg;
    info->cb= cb;
}
static inline void ipc_msg_set_payload(ipc_msg *msg, uint8_t *data, int data_len)
{
    ipc_msg_info *info = (ipc_msg_info *)msg;

    info->data     = data;
    info->data_len = data_len;
}

static inline void ipc_msg_set_rsp_status(ipc_msg *msg, int status, int seq_num) 
{
    ipc_msg_info *info = (ipc_msg_info *)msg;

    info->seq_num = seq_num;
    info->status  = status;
}

ipc_handle ipc_init();

void ipc_free_msg(ipc_msg *msg);
ipc_msg* ipc_create_msg(ipc_ep ep, int msg_id, int type);
ipc_msg* ipc_create_req_msg(ipc_ep ep, int msg_id, ipc_msg_cb cb);
ipc_msg* ipc_create_rsp_msg(ipc_ep ep, int msg_id, int status, int seq_num);
int ipc_send_msg_sync(ipc_msg *msg, void *rsp_data);
int ipc_send_msg_async(ipc_msg *msg);
int ipc_broadcast_msg(ipc_msg *msg);

ipc_ep ipc_register_service(ipc_context *ipc, ipc_topics topic, ipc_msg_cb cb);
ipc_ep ipc_request_service(ipc_context *ipc, ipc_topics topic, ipc_msg_cb cb);

int ipc_req_add(ipc_ep ep, ipc_req_info *req);

int ipc_gen_msg(ipc_msg *msg, uint8_t *buf, uint16_t buf_len);

int ipc_msg_parse(uint8_t *buf, uint16_t buf_len, ipc_msg_info *info);

int ipc_prepare_req_msg(ipc_msg *msg, int id, ipc_msg_cb cb);

void ipc_dump_msg_info(ipc_msg_info *info);

int ipc_add_ev_io_watcher(ipc_context *ipc, int fd, ev_io *watcher, my_ev_io_cb cb);

void ipc_free_msg(ipc_msg *msg);

/* common structs/defines/functions that helps with IPC development */

typedef struct {
    void *ipc;
    void *mempool;
    void *queue;
} ipc_info;

#endif