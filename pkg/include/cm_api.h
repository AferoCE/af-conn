/*
 *
 * Common defines for connection manager
 * 
 */

#ifundef CM_API_H
#define CM_API_H

#include <stdint.h>

typedef enum {
    CM_CMD_REQUEST_CONNECTION = 0,
    CM_CMD_RELEASE_REQUEST,
    CM_CMD_REPORT_BAD_CONNECTION,
    CM_IND_CONNECTION_UPDATE,
    CM_CMD_MAX,
} cm_msg_id_t;

typedef enum {
    CM_STATUS_SUCCESS = 0,
    CM_STATUS_INTERNAL_ERROR,
    CM_STATUS_MAX
} cm_status_code;

/* */
#define CONNECTION_ID_LEN 32
typedef struct connections_struct {
    uint32_t capabilities;
    uint32_t links;
    uint8_t  data_len;
    uint8_t  data[CONNECTION_ID_LEN];
} cm_connection_req_info_t;

typedef struct cm_connection_struct {
    cm_connection_req_info_t conn;
    cm_connection_state_t    state;
} cm_connection_t;

typedef void (*cm_connection_notify_cb)(cm_connection_t *info);

/* a way for caller to notify CM about potential connection issues */
void cm_report_bad_connection(cm_connection_info_t *connection_info);

/*
 [in]:
 - specifies what kind of connection is required
 - cb for notification on changes to the required connection

 [out]:
 - handle for identifying this request
*/
void* cm_request_connection(cm_connection_req *req, cm_connection_notify_cb cb);

int cm_release_request(void *handle);

// Move this to event daemon?
/* callback for listen to connection state changes */
typedef void (*connection_manager_event_cb)(cm_connection_t *connection);

/* add route */
int cm_add_routev4(int dest, int subnet, char *ifname);

/* internal
    1) power: on, off, lpm
    2) session: setup, tear down
 */

int cm_link_setup();




#endif