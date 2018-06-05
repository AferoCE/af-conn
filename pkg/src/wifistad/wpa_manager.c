/*
 * wpa_manager.c
 *
 * The component of WIFISTAD that interacts with the WPA supplicant.
 * It opens two connections to wpa_supplicant: control and monitor.
 *
 * The control connection is used to send WPA supplicant commands,
 * while the monitor connection receives messages.  The messages
 * are relayed as event to the event loop.
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <malloc.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>

#include "af_ipc_common.h"
#include "af_ipc_server.h"
#include "wpa_ctrl.h"
#include "wpa_manager.h"
#include "common.h"
#include "af_log.h"
#include "wifistad_common.h"
#include "af_util.h"
#include "../include/netif_names.h"


#define CONFIG_CTRL_IFACE_DIR "/var/run/wpa_supplicant"
extern uint8_t	wifista_bootup;
extern void wifista_reset_ap_list();
extern void prv_wpa_event_callback(evutil_socket_t fd, short evts, void *param);


#undef _SUB
#define _SUB(_x) #_x
char *WPA_EVENT_ID_STR[WPA_EVENT_ID_MAX] = {
        WPA_EVENT_IDS
};

#define  CTRL_RSP_BUF_LEN    4096


static wpa_manager_t s_wpa_manager;
static wpa_client_t s_wpa_client; // we only support 1 client for now. this theoretically could be an array for multiple clients.
static char s_ctrl_rsp_buf[CTRL_RSP_BUF_LEN]; // buffer for processing responses
static int s_warning_displayed = 0;

static int prv_str_starts(const char *src, const char *match);
static void prv_process_unsolicited(const char *str);
static void prv_unsolicited_recv_cb(evutil_socket_t fd, short what, void *arg);

static int prv_process_rsp_add_network(char *rsp);
static int prv_process_rsp_default(char *rsp);

static int prv_send_req_status(void);
static int prv_send_req_list_networks(void);
static int prv_send_req_set_network_param(int id, char *variable, char *value, int is_quoted);
static int prv_send_req_select_network(int id);
static int prv_send_req_enable_network(int id);
static int prv_send_req_add_network(void);
static int prv_send_req_reconnect(void);
static int prv_send_req_disconnect(void);
static int prv_send_req_signal_poll(void);

static void prv_ctrl_cmd_cb(char *msg, size_t len);

static void prv_reconnect(void);
static void prv_close_connection(void);
static int  prv_open_connection(const char *iface_name);
static void prv_try_connection_cb(evutil_socket_t fd, short what, void *arg);
static void *prv_op_scan_results(wpa_op_desc_t *op_desc);

static int prv_util_get_network_id(char *ssid);

char *s_wpa_op_names[] = {
    WPA_OPS
};



static int prv_lookup_network(char *key, network_lookup_key_type_e network_lookup_key_type)
{
	char *key_token = NULL;
	int  len = 0;
	char network_list_buf[CTRL_RSP_BUF_LEN];
	char *saveptr1, *saveptr2 = NULL, *line;


	memset(network_list_buf, 0, sizeof(network_list_buf));
	if (key == NULL) {
		AFLOG_DEBUG3("prv_lookup_network::invalid input key");
		return (-1);
	}
	if (prv_send_req_list_networks() < 0) {
		AFLOG_DEBUG3("prv_lookup_network::failed to refresh networks");
		return -1;
	}

	strncpy(network_list_buf, s_ctrl_rsp_buf, CTRL_RSP_BUF_LEN-1);
	AFLOG_DEBUG3("prv_lookup_network:: list_buf=%s", network_list_buf);

	/* tokenize into lines and parse */
	line = strtok_r(network_list_buf, "\n", &saveptr1);   // title
	while (1) {
		/* get line */
		line = strtok_r(NULL, "\n", &saveptr1);
		if (line == NULL)
			break;

		char *tok[4] = {NULL, NULL, NULL, NULL};
		int i;
		for (i = 0; i < 4; i++, line = NULL) {
			tok[i] = strtok_r(line, "\t", &saveptr2);
		}

		switch(network_lookup_key_type) {
		case NETWORK_LOOKUP_KEY_TYPE_SSID:
			if (tok[1] != NULL) {
				key_token = tok[1];
				len = strlen (key_token);
				len = (len > WIFISTA_SSID_LEN) ? WIFISTA_SSID_LEN : len;
			}
			break;
		case NETWORK_LOOKUP_KEY_TYPE_BSSID:
			if (tok[2] != NULL) {
				key_token = tok[2];
				len = strlen (key_token);
				len = (len > WIFISTA_BSSID_LEN) ? WIFISTA_BSSID_LEN : len;
			}
			break;
		default:
			return -2;
		}

		if ((key_token) && strncmp(key_token, key, len) == 0) {
#if 0
			printf("tok[0] = %s\n", tok[0]); // network_id
			printf("tok[1] = %s\n", tok[1]); // ssid
			printf("tok[2] = %s\n", tok[2]); // bssid
			printf("tok[3] = %s\n", tok[3]); // flags
#endif
			return atoi(tok[0]);
		}
	}

	return -1;
}


static int prv_get_rssi (void)
{
    char *saveptr1, *saveptr2, *line;
    int     rssi_val= 0;

    if (prv_send_req_signal_poll() < 0) {
        return rssi_val;
    }

    if ((line = strstr(s_ctrl_rsp_buf, "RSSI="))) {
        char *tok[2] = {NULL, NULL};
        int i;

        line = strtok_r(s_ctrl_rsp_buf, "\n", &saveptr1);
        while (1) {
            /* get line */
            if (line == NULL)
                break;

            for (i = 0; i < 2; i++, line = NULL) {
                tok[i] = strtok_r(line, "=", &saveptr2);
            }
            if ((tok[0]) && (strncmp(tok[0], "RSSI", 4) == 0)) {
                rssi_val = atoi(tok[1]);
                break;
            }
            line = strtok_r(NULL, "\n", &saveptr1);
        }
    }
    return rssi_val;
}

/**************** WPA Supplicant Unsolicited Helpers ****************/
static int prv_str_starts(const char *src, const char *match)
{
    return strncmp(src, match, strlen(match)) == 0;
}

static void prv_scan_results(void)
{
    wpa_manager_t *m = &s_wpa_manager;

    pthread_mutex_lock(&m->op_cond_mutex);

	m->current_op.op = WPA_OP_SCAN_RESULTS;
	m->current_op.func = prv_op_scan_results;
	m->current_op.cb = NULL;
	m->current_op.pending = m->current_op.pending + 1;
	AFLOG_DEBUG1("prv_scan_results:: enable pending op =%d, %s",
			m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);
}


// post an wpa event
// wpa_event_cb = prv_wpa_event_callback (wap_manager_init)
void wifista_wpa_post_event(wpa_event_id_e id, void *result)
{
	wpa_manager_t *m = &s_wpa_manager;

	wpa_event_t *event = malloc(sizeof(*event));
	if (event == NULL) {
		AFLOG_ERR("wifista_wpa_post_event: malloc failed event %d", id);
		return;
	}

	event->id = id;
	event->result = result;

	// toss this back to the main event loop
	struct timeval tv = { 0, 0 };
	event_base_once(m->evbase, -1, EV_TIMEOUT, prv_wpa_event_callback, (void *)event,
					event_base_init_common_timeout(m->evbase, &tv));

	return;
}


/***
 *
 *
 */
static void prv_process_unsolicited(const char *str)
{
    const char *start;
    const char *temp = NULL;
    static uint8_t  trying_auth_or_assoc = 0;


    AFLOG_DEBUG2("prv_process_unsolicited::WPA: str=%s", str);
    start = strchr(str, '>');
    if (start == NULL) {
        return;
    }

    start++;

    if (prv_str_starts(start, WPA_EVENT_CONNECTED)) {
        int   id = WPA_CONN_RESULT_NO_ID;

        start = strstr(start, "[id=");
        if (start) {
            id = atoi(start+4);
        }

       wifista_wpa_post_event(WPA_EVENT_ID_CONNECTED, (void *)id);
    } else if (prv_str_starts(start, WPA_EVENT_ASSOC_REJECT)) {
        wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *)WPA_CONN_RESULT_ASS_REJECT);
    } else if (prv_str_starts(start, WPA_EVENT_TEMP_DISABLED)) {
        wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *)WPA_CONN_RESULT_TEMP_DISABLED);
    } else if (prv_str_starts(start, WPA_EVENT_SCAN_RESULTS)) {
        prv_scan_results();
    } else if (prv_str_starts(start, WPA_EVENT_DISCONNECTED)) {
        wifista_wpa_post_event(WPA_EVENT_ID_DISCONNECTED, NULL);
    }
    else if ( ((temp = strstr(start, "Trying to associate with")) != NULL) ||
              ((temp = strstr(start, "Trying to authenticate with")) != NULL) )  {
        int   id = WPA_CONN_RESULT_NO_ID;
        char *ssid;
        char *saveptr;
        char line[125];
        memset(line, 0, sizeof(line));
        if (temp) {
            strcpy(line, temp);
            ssid = strtok_r(line, "'", &saveptr);
            ssid = strtok_r(NULL, "'", &saveptr);

            //id = prv_lookup_network(ssid, NETWORK_LOOKUP_KEY_TYPE_SSID);
            id = prv_util_get_network_id(ssid);
            AFLOG_DEBUG2("prv_process_unsolicited:: Trying to associate ...., ssid=%s, id=%d",
                         ssid, id);
        }

        // In case both these happen at the same connect attempt, then post once only
        if (trying_auth_or_assoc == 0) {
            wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING, (void *) id);
            trying_auth_or_assoc = 1;
        }
    }
    else if (strstr(start, "4-Way Handshake failed") != NULL) {
        AFLOG_INFO("prv_process_unsolicited:: 4-Way Handshake failed \n");
        wifista_wpa_post_event(WPA_EVENT_ID_CONNECTING,
                               (void *)WPA_CONN_RESULT_HANDSHAKE_FAILED);
    }
    else if (strstr(start, WPA_EVENT_TERMINATING)) {
        AFLOG_DEBUG1("prv_process_unsolicited:: post event TERMINATED");
        wifista_wpa_post_event(WPA_EVENT_ID_TERMINATED, NULL);
    }

    // reset the flag if not one of the "trying to ..."
    if (temp == NULL) {
        trying_auth_or_assoc = 0;
    }
}


/***
 * Read from the unsolicited pending messages
 */
static void prv_unsolicited_recv_cb(evutil_socket_t fd, short what, void *arg)
{
    struct wpa_ctrl *mon_conn = s_wpa_manager.mon_conn;


    if (mon_conn == NULL) {
        AFLOG_ERR("prv_unsolicited_recv_cb:: detect mon_conn == NULL");
        return;
    }

    while (wpa_ctrl_pending(mon_conn) > 0) {
        char buf[256];
        size_t len = sizeof(buf) - 1;
        if (wpa_ctrl_recv(mon_conn, buf, &len) == 0) {
            buf[len] = '\0';
            prv_process_unsolicited(buf);
        } else {
            AFLOG_ERR("Could not read pending message - lost connection");
            break;
        }
    }

    if (wpa_ctrl_pending(mon_conn) < 0) {
        AFLOG_INFO("prv_unsolicited_recv_cb::WPA:Connection to wpa_supplicant lost - trying to reconnect");
        prv_reconnect();
    }
}

/****************** WPA Supplicant Response Helpers ******************/

static int prv_process_rsp_add_network(char *rsp)
{
    int id = -1;

    if (rsp != NULL) {
        if (sscanf(rsp, "%d", &id) < 0) {
            AFLOG_ERR("prv_process_rsp_add_network:: failed to parse add_network::rsp=%s", rsp);
            return -1;
        }
    }
    return id;
}


// internal utility to get the network id from the wpa_manager's wifi setup
// control data given the ssid
static int prv_util_get_network_id(char *ssid)
{
    wpa_manager_t   *m = &s_wpa_manager;

     if (m->wifi_setup.network_id != -1) {
        // Hack: should really check the ssid here before return
        return (m->wifi_setup.network_id);
    }
    else if (m->assoc_info.id > 0) {
        if (strncmp(m->assoc_info.ssid, ssid, strlen(ssid)) ==0) {
            return m->assoc_info.id;
        }
    }
    else {
        return prv_lookup_network(ssid, NETWORK_LOOKUP_KEY_TYPE_SSID);
    }

    return (-1);
}

static int prv_process_rsp_status(char *rsp)
{
    char *saveptr1, *saveptr2, *line;
    wpa_manager_t   *m = &s_wpa_manager;
    uint8_t         connected = 0;


    if (rsp == NULL) {
        return 0;
    }

    AFLOG_DEBUG3("prv_process_rsp_status: %s", rsp);

    /* clear previous association data */
    memset(&m->assoc_info, 0, sizeof(wpa_sta_assoc_t));

    /* tokenize into lines and parse */
    line = strtok_r(rsp, "\n", &saveptr1);
    while (1) {
        char *tok[2] = { NULL, NULL};
        int i;

        if (line == NULL) {
            break;
        }

        for (i = 0; i < 2; i++, line = NULL) {
            tok[i] = strtok_r(line, "=", &saveptr2);
        }

        if ((tok[0] == NULL) || (tok[1] == NULL)) {
            AFLOG_ERR("prv_process_rsp_status:: invalid token, line=%s", (line==NULL)?"NULL":line);
            break;
        }

        /* store the data */
        int  len = 0;
        len = strlen(tok[1]);
        len = ((len > WPA_STATUS_STR_LEN) ? WPA_STATUS_STR_LEN : len);

        if (strncmp(tok[0], "bssid", 5) == 0) {
            m->assoc_info.associated = 1;  // we are associated.
            strncpy(m->assoc_info.bssid, tok[1], 17);
        }
        else if (strncmp(tok[0], "freq", 4) == 0) {
            m->assoc_info.freq = atoi(tok[1]);
        }
        else if (strncmp(tok[0], "ssid", 4) == 0) {
            len = strlen(tok[1]);
            len = ((len > WIFISTA_SSID_LEN) ? WIFISTA_SSID_LEN : len);
            strncpy(m->assoc_info.ssid, tok[1], len);
        }
        else if (strncmp(tok[0], "id", 2) == 0) {
            m->assoc_info.id = atoi(tok[1]);
        }
        else if (strncmp(tok[0], "mode", 4) == 0) {
            strncpy(m->assoc_info.mode, tok[1], len);
            if (strstr(tok[1], "station")) {
                connected = 1;
            }
        }
        else if (strncmp(tok[0], "pairwise_cipher", 15) == 0) {
            strncpy(m->assoc_info.pairwise_cipher, tok[1], len);
        }
        else if (strncmp(tok[0], "key_mgmt", 8) == 0) {
            strncpy(m->assoc_info.key_mgmt, tok[1], len);
        }
        else if (strncmp(tok[0], "group_cipher", 12) == 0) {
            strncpy(m->assoc_info.group_cipher, tok[1], len);
        }
        else if (strncmp(tok[1], "wpa_state", 9) == 0) {
            strncpy(m->assoc_info.wpa_state, tok[1], len);
        }
        else if (strncmp(tok[0], "ip_address", 10) == 0) {
            strncpy(m->assoc_info.ip_address, tok[1], 17);
        }
        else if (strncmp(tok[0], "p2p_device_address", 18) == 0) {
            strncpy(m->assoc_info.p2p_device_address, tok[1], 17);
        }
        else if (strncmp(tok[0], "address", 7) == 0) {
            strncpy(m->assoc_info.address, tok[1], 17);
        }

        /* get next line */
        line = strtok_r(NULL, "\n", &saveptr1);
    }

    if ((connected) && (wifista_bootup == 1)) { // only do this if wifista restarted
        wifista_wpa_post_event(WPA_EVENT_ID_CONNECTED, (void *)m->assoc_info.id);
    }
    wifista_bootup = 0;  // only do it once
    return (m->assoc_info.id);
}

static int prv_process_rsp_scan(char *rsp)
{
    if (prv_str_starts(rsp, "OK")) {
        return 0;
    }
    return -1;
}

static int prv_process_rsp_scan_results(char *rsp)
{
    if (rsp != NULL) {
        AFLOG_DEBUG3("prv_process_rsp_scan_results: scan result, rsp=%s", rsp);
        wifista_wpa_post_event(WPA_EVENT_ID_SCAN_RESULTS, (void *) rsp);
    }

	return 0;
}

static int prv_process_rsp_default(char *rsp)
{
    if (strstr(rsp, "OK") == NULL) {
        return -1;
    }
    return 0;
}

/******************* WPA Supplicant Request Helpers *******************/
static void prv_ctrl_cmd_cb(char *msg, size_t len)
{
    printf("%s\n", msg);
}


static int prv_ctrl_send_cmd(wpa_async_req_t *req)
{
    char    *buf;
    size_t  len;
    int     ret = 0;
    struct wpa_ctrl *ctrl_conn = s_wpa_manager.ctrl_conn;


    if ((ctrl_conn == NULL) || (s_wpa_manager.started == 0)) {
        ret = -1;
        goto error_exit;
    }

    buf = s_ctrl_rsp_buf;
    len = sizeof(s_ctrl_rsp_buf) - 1;
    ret = wpa_ctrl_request(ctrl_conn, req->cmd, strlen(req->cmd), buf, &len, prv_ctrl_cmd_cb);

    if (ret == -2) {
        goto error_exit;
    } else if (ret < 0) {
        goto error_exit;
    }

    buf[len] = '\0';

#if 0
    printf("%s ####################\n", __FUNCTION__);
    printf(">>> %s\n", req->cmd);
    printf("--------------------\n");
    printf("<<< %s\n", buf);
    printf("%s ####################\n", __FUNCTION__);

    if (len > 0 && buf[len - 1] != '\n')
        printf("\n");
#endif

    /* process response */
    switch (req->id) {
    case WPA_CMD_ADD_NETWORK:
        ret = prv_process_rsp_add_network(buf);
        break;
    case WPA_CMD_SET_NETWORK:
    case WPA_CMD_SELECT_NETWORK:
    case WPA_CMD_ENABLE_NETWORK:
    case WPA_CMD_DISABLE_NETWORK:
    case WPA_CMD_REMOVE_NETWORK:
        ret = prv_process_rsp_default(buf);
        if (ret < 0) {
            // SET_NETWORK command may contain auth credential
            AFLOG_WARNING("prv_ctrl_send_cmd:: cmd=%s failed",
                          (req->id != WPA_CMD_SET_NETWORK) ? req->cmd : "SET_NETWORK");
        }
        break;
    case WPA_CMD_STATUS:
        ret = prv_process_rsp_status(buf);
        break;
    case WPA_CMD_SCAN:
        ret = prv_process_rsp_scan(buf);
        break;
    case WPA_CMD_SCAN_RESULTS:
        ret = prv_process_rsp_scan_results(buf);
        break;
    case WPA_CMD_SIGNAL_POLL:
        AFLOG_DEBUG3("SIGAL_POLL: rsp_buf=%s", buf);
        break;
    case WPA_CMD_PING:
        AFLOG_DEBUG3("PING: rsp_buf=%s", buf);
        if (strncmp(buf, "PONG", 4) != 0) {
            if (len == 0) {
                ret = -1;
            }
            else {  // we didn't get PONG, but something else
               ret = len;
            }
        }
        break;

    default:
        break;
    }

error_exit:
    return ret;
}

int prv_send_req_ping_networks(void)
{
    wpa_async_req_t req;
    char cmd[] = "PING";

    req.id = WPA_CMD_PING;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}


static int prv_send_req_list_networks(void)
{
    wpa_async_req_t req;
    char cmd[] = "LIST_NETWORKS";

    req.id = WPA_CMD_LIST_NETWORKS;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_set_network_param(int id, char *variable, char *value, int is_quoted)
{
    wpa_async_req_t req;
    char *cmd;
    int ret;
    char *quoted_cmd = "SET_NETWORK %d %s \"%s\"";
    char *unquoted_cmd = "SET_NETWORK %d %s %s";

    if (asprintf(&cmd, is_quoted ? quoted_cmd : unquoted_cmd, id, variable, value) < 0)
        return -1;

    req.id = WPA_CMD_SET_NETWORK;
    req.cmd = cmd;

    ret = prv_ctrl_send_cmd(&req);

    free(cmd);
    return ret;
}

static int prv_send_req_select_network(int id)
{
    wpa_async_req_t req;
    char *cmd;
    int ret;

    if (asprintf(&cmd, "SELECT_NETWORK %d", id) < 0)
        return -1;

    req.id = WPA_CMD_SELECT_NETWORK;
    req.cmd = cmd;

    ret = prv_ctrl_send_cmd(&req);

    free(cmd);
    return ret;
}

static int prv_send_req_enable_network(int id)
{
    wpa_async_req_t req;
    char *cmd;
    int ret;

    if (asprintf(&cmd, "ENABLE_NETWORK %d", id) < 0)
        return -1;

    req.id = WPA_CMD_ENABLE_NETWORK;
    req.cmd = cmd;

    ret = prv_ctrl_send_cmd(&req);

    free(cmd);
    return ret;
}

/* return: id of new network, or -1 if failed */
static int prv_send_req_add_network(void)
{
    wpa_async_req_t req;
    char cmd[] = "ADD_NETWORK";

    req.id = WPA_CMD_ADD_NETWORK;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_reconnect(void)
{
    wpa_async_req_t req;
    char cmd[] = "RECONNECT";

    AFLOG_DEBUG2("prv_send_req_reconnect:: %s", cmd);
    req.id = WPA_CMD_RECONNECT;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_status(void)
{
    wpa_async_req_t req;
    char cmd[] = "STATUS";

    req.id = WPA_CMD_STATUS;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_scan(void)
{
    wpa_async_req_t req;
    char cmd[] = "SCAN";

    req.id = WPA_CMD_SCAN;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_scan_results(void)
{
    wpa_async_req_t req;
    char cmd[] = "SCAN_RESULTS";

    req.id = WPA_CMD_SCAN_RESULTS;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_disconnect(void)
{
    wpa_async_req_t req;
    char cmd[] = "DISCONNECT";

    req.id = WPA_CMD_DISCONNECT;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_signal_poll(void)
{
    wpa_async_req_t req;
    char cmd[] = "SIGNAL_POLL";

    req.id = WPA_CMD_SIGNAL_POLL;
    req.cmd = cmd;

    return prv_ctrl_send_cmd(&req);
}

static int prv_send_req_remove_network(int id)
{
    wpa_async_req_t req;
    char    *cmd;
    int     ret;
    char    *formatted_cmd = "REMOVE_NETWORK %d";

    if (asprintf(&cmd, formatted_cmd, id) < 0) {
        return -1;
    }

    AFLOG_DEBUG2("prv_send_req_remove_network:: %s", cmd);
    req.id = WPA_CMD_REMOVE_NETWORK;
    req.cmd = cmd;

    ret = prv_ctrl_send_cmd(&req);

    free(cmd);
    return ret;
}


/***************** prv_wpa_worker_loop wpa_op_desc_t.cbs ******************/
static void *prv_op_connect(wpa_op_desc_t *op_desc)
{
    return (void *)prv_send_req_select_network(op_desc->func_params.connect_params.network_id);
}

static void *prv_op_configure_network(wpa_op_desc_t *op_desc)
{
    int id = 0;
    int found_ssid = 0;
    int found_bssid = 0;
    int rc = WPA_CONN_RESULT_INIT;
    int cfg_network_failed = 0;


    if (op_desc == NULL) {
        AFLOG_ERR("prv_op_configure_network:: Invalid input");
        return (void *)-1;
    }

    if (op_desc->func_params.configure_network_params.ssid[0] == 0) {
        AFLOG_WARNING("prv_op_configure_network::ssid cannot be null\n");
        rc = WPA_CONN_RESULT_INVALID_SSID;
        goto configure_network_done;
    }

    if (op_desc->func_params.configure_network_params.bssid[0] == 0) {
        id = prv_lookup_network(op_desc->func_params.configure_network_params.ssid, NETWORK_LOOKUP_KEY_TYPE_SSID);
        found_ssid = (id > 0);
    } else {
        id = prv_lookup_network(op_desc->func_params.configure_network_params.bssid, NETWORK_LOOKUP_KEY_TYPE_BSSID);
        found_bssid = (id > 0);
    }

    if (!found_ssid && !found_bssid) {
        AFLOG_DEBUG2("prv_op_configure_network::network not found, adding new network");
        id = prv_send_req_add_network();
        if (id < 0) {
            rc = WPA_CONN_RESULT_NO_ID;
            cfg_network_failed = 1;
            AFLOG_DEBUG2("prv_op_configure_network:: ADD_NETWORK failed, network id=%d", id);
            goto configure_network_done;
        }
    }

    if (!found_ssid) {
        if (prv_send_req_set_network_param(id, "ssid", op_desc->func_params.configure_network_params.ssid, 1) < 0) {
            rc = WPA_CONN_RESULT_INVALID_SSID;
            AFLOG_WARNING("prv_op_configure_network:: failed to set ssid");
            goto configure_network_done;
        }
    }

    if (prv_send_req_set_network_param(id, "bssid", "any", 0) < 0) {
        AFLOG_WARNING("prv_op_configure_network::failed to set network bssid");
        rc = WPA_CONN_RESULT_NO_ID;
        goto configure_network_done;
    }

    /* TBD - need to get security type? */
    if (op_desc->func_params.configure_network_params.psk != NULL) {
        if (*op_desc->func_params.configure_network_params.psk != '\0') {
            if (prv_send_req_set_network_param(id, "psk", op_desc->func_params.configure_network_params.psk, 1) < 0) {
                AFLOG_WARNING("prv_op_configure_network::failed to set network psk");
                // cfg_network_failed = 1;
                rc = WPA_CONN_RESULT_SET_PSK_FAILED;
                goto configure_network_done;
            }
        } else {
            AFLOG_DEBUG1("prv_op_configure_network::connecting to open network");
            if (prv_send_req_set_network_param(id, "key_mgmt", "NONE", 0) < 0) {
                AFLOG_WARNING("prv_op_configure_network::failed to set key_mgmt to NONE");
                rc = WPA_CONN_RESULT_SET_PSK_FAILED;
                goto configure_network_done;
            }
        }
    }
    else {
        AFLOG_WARNING("prv_op_configure_network::invalid network psk");
        rc = WPA_CONN_RESULT_SET_PSK_FAILED;
        goto configure_network_done;
    }

    if (op_desc->func_params.configure_network_params.priority > 0) {
        char priority_string[3];

        snprintf(priority_string, sizeof(priority_string), "%d", op_desc->func_params.configure_network_params.priority);
        if (prv_send_req_set_network_param(id, "priority", priority_string, 0) < 0) {
            AFLOG_WARNING("prv_op_configure_network:: failed to set priority");
            rc = -1;
            goto configure_network_done;
         }
    }

#if 0
    printf("Exiting %s:: WPA:  found_ssid=%d, found_ssid=%d\n", __FUNCTION__, found_bssid, found_ssid);
    printf("  ----  id=%d  bssid=%s  ssid=%s \n", id,
           op_desc->func_params.configure_network_params.bssid,
           op_desc->func_params.configure_network_params.ssid);
    printf("  ----  psk=%s  priority=%d \n",
           op_desc->func_params.configure_network_params.psk,
           op_desc->func_params.configure_network_params.priority);
#endif

    if (!found_ssid && !found_bssid) {
        if (prv_send_req_enable_network(id) < 0) {
            AFLOG_INFO("prv_send_req_enable_network:: enable network failed");
            rc = -1;
            goto configure_network_done;
        }
    }

    op_desc->func_params.connect_params.network_id = id;
    if (prv_op_connect(op_desc)) {
        AFLOG_DEBUG1("prv_op_configure_network:: request connect to network (id=%d, ssid=%s)",
                     id, op_desc->func_params.configure_network_params.ssid);
        rc = -1;
    }


configure_network_done:
	if (cfg_network_failed) {
		exit(EXIT_FAILURE);
	}
	else {
		// if failed for any reason, let's delete the added network
		if (rc < WPA_CONN_RESULT_INIT) {
			if (id > 0) {
				prv_send_req_remove_network(id);
			}
			return (void *)rc;
		}
		else {
			return (void *) id;
		}
	}
}

static void *prv_op_reconnect(wpa_op_desc_t *op_desc)
{
    return (void *)prv_send_req_reconnect();
}

static void *prv_op_status(wpa_op_desc_t *op_desc)
{
    return (void *)prv_send_req_status();
}

static void *prv_op_scan(wpa_op_desc_t *op_desc)
{
    return (void *)prv_send_req_scan();
}

static void *prv_op_scan_results(wpa_op_desc_t *op_desc)
{
    return (void *)prv_send_req_scan_results();
}

static void *prv_op_disconnect(wpa_op_desc_t *op_desc)
{
	if ((op_desc) && (op_desc->op == WPA_OP_DISCONNECT)) {
		return (void *)prv_send_req_disconnect();
	}

	return (void *)0;
}


static void *prv_op_remove_network(wpa_op_desc_t *op_desc)
{
    if (op_desc == NULL) {
        AFLOG_ERR("prv_op_remove_network:: Invalid input");
        return (void *)-1;
    }

    return (void *)prv_send_req_remove_network(op_desc->func_params.connect_params.network_id);
}

/***************** WPA Supplicant Connection Helpers *****************/
static void prv_reconnect(void)
{
    AFLOG_DEBUG2("prv_reconnect:: Entering prv_reconnect");
    prv_close_connection();
    if (prv_open_connection(s_wpa_manager.ctrl_iface_name) < 0)
        return;

    AFLOG_INFO("Connection to wpa_supplicant re-established");
}

static void prv_close_connection(void)
{
    wpa_manager_t *m = &s_wpa_manager;
    if (m->ctrl_conn) {
        AFLOG_INFO("prv_close_connection: wpa_ctrl_close(ctrl_conn)");
        wpa_ctrl_close(m->ctrl_conn);
        m->ctrl_conn = NULL;
    }
    if (m->mon_conn) {
        // this means wpa_supplicant is not terminated and we still connect to it.
        // Typically, when the wpa_supplicant is terminated (either kill by
        // operator or crashed), wifistad receives a terminated event.
        if (m->started == 1) {
            AFLOG_INFO("prv_close_connection: wpa_ctrl_detach()");

            // note: this calls wpa_ctrl_request to send the "DETACH" cmd.
            // And in our design, the wpa_ctrl_request should run on second thread,
            // with mutex.  Cheating by calling it here - not protected.
            wpa_ctrl_detach(m->mon_conn);
		}
        AFLOG_INFO("prv_close_connection: wpa_ctrl_close(mon_conn)");
        wpa_ctrl_close(m->mon_conn);
        m->mon_conn = NULL;
	}

    if (m->wpa_event) {
        event_del(m->wpa_event);
        event_free(m->wpa_event);
        m->wpa_event = NULL;
    }
}


/***
 * Open two connections to WPA supplicant.  If the connections are
 * sucessfully, then schedule a READ event to receive the event.
 *
 * Note:
 * wpa_cli works in the interactive and non-interactive mode.
 * It seems that when you are using the interactive mode, wpa_cli use
 * both ctrl_conn and mon_conn:
 * - ctrl_conn is used to send commands only, and
 * - mon_conn is used to get events (i.e it is the one to be attached via
 *   wpa_ctrl_attach()).
 */
static int prv_open_connection(const char *iface_name)
{
    wpa_manager_t *m = &s_wpa_manager;
    char *filename = NULL;
    int rc = -1;


    if (iface_name == NULL)
        return -1;

    if (asprintf(&filename, "%s/%s", CONFIG_CTRL_IFACE_DIR, iface_name) < 0)
        return -1;

    m->ctrl_conn = wpa_ctrl_open(filename);
    if (m->ctrl_conn == NULL) {
        goto error_exit;
    }

    m->mon_conn = wpa_ctrl_open(filename);
    if (m->mon_conn == NULL) {
        goto error_exit;
    }

    if (wpa_ctrl_attach(m->mon_conn) != 0) {
        AFLOG_ERR("prv_open_connection::Failed to attach to wpa_supplicant");
        goto error_exit;
    }

    m->wpa_event = event_new(m->evbase, wpa_ctrl_get_fd(m->mon_conn),
                             (EV_READ|EV_PERSIST),
                             prv_unsolicited_recv_cb, (void*)m->evbase);
    if (event_add(m->wpa_event, NULL)) {
        AFLOG_ERR("prv_open_connection::Error scheduling connect event on the event loop.\n");
        event_free(m->wpa_event);
        m->wpa_event = NULL;
        goto error_exit;
    }

    AFLOG_INFO("prv_open_connection:: WPA open connetion successful");

    // Now we can declare the wpa_manager is full initialized.
    m->started = 1;
    rc = 0;

error_exit:
    if (rc != 0){
        AFLOG_INFO("prv_open_connection:: WPA open connetion failed");
        prv_close_connection();
    }

    if (filename) {
        free(filename);
        filename = NULL;
    }

    return rc;
}

/*
 * Try to open a connection to the ctrl interface.
 *  - if open connection failed
 *      enable a 4 second timer to try again
 */
static void prv_try_connection_cb(evutil_socket_t fd, short what, void *arg)
{
    wpa_manager_t   *m = &s_wpa_manager;
    struct timeval  tmout_ms = {4, 0};

    AFLOG_DEBUG3("%s_enter", __func__);
    if (m->ctrl_conn)
        return;

    if (m->ctrl_iface_name == NULL) {
        m->ctrl_iface_name = NETIF_NAME(WIFISTA_INTERFACE_0);
    }

    if (!prv_open_connection(m->ctrl_iface_name) == 0) {
        event_base_once(m->evbase, -1, EV_TIMEOUT, prv_try_connection_cb, NULL, &tmout_ms);
        if (!s_warning_displayed) {
            AFLOG_WARNING("prv_try_connection_cb::Could not connect to wpa_supplicant: "
                    "%s - re-trying \n", m->ctrl_iface_name);
            s_warning_displayed = 1;
        }

        return;
    }

    s_warning_displayed = 0;
    AFLOG_INFO("prv_try_connection_cb::Connection to wpa_supplicant established");

    wifista_wpa_post_event(WPA_EVENT_ID_READY, (void *)&(m->wifi_setup));
}


/***
 *  thread to
 */
static void *prv_wpa_worker_loop(void *arg)
{
    wpa_manager_t *m = &s_wpa_manager;
    void *result_param;

    AFLOG_INFO("prv_wpa_worker_loop:: init, m->started=%d, pending=%d",
               m->started, m->current_op.pending);
    while (1) {
        wpa_op_desc_t op_desc;

        pthread_mutex_lock(&m->op_cond_mutex);

        while(!m->current_op.pending) {
            AFLOG_INFO("prv_wpa_worker_loop:: waiting for enable pending(=%d)", m->current_op.pending);
            pthread_cond_wait(&m->op_cond, &m->op_cond_mutex);
        }

        op_desc = m->current_op;
        m->current_op.pending = 0;
        AFLOG_INFO("prv_wpa_worker_loop:: op=(%d, %s), re-setting pending=%d",
                   m->current_op.op, s_wpa_op_names[m->current_op.op],
                   m->current_op.pending);

        pthread_mutex_unlock(&m->op_cond_mutex);

        result_param = op_desc.func(&op_desc);

         AFLOG_DEBUG2("prv_wpa_worker_loop::  IN LOOP, cb=%p, result_param=%p", op_desc.cb,
                    result_param);
        if (op_desc.cb) {
            op_desc.cb(op_desc.cb_param, result_param);
        }
    }

    return NULL;
}

/****************************** Public API ******************************/
int wpa_manager_configure_ssid_async(wpa_manager_asyc_cb_t cb, void *param, char *ssid, char *psk, int priority)
{
    return wpa_manager_configure_bssid_async(cb, param, ssid, psk, NULL, priority);
}


/***
 * we have a bssid (i.e  MAC address (H/W Address) of the Wi-Fi Chipset
 * running on a Wireless Access Point), let's see if we can configure it?
 *
 * invoked with:
 *  cb    = prv_master_configure_complete,
 *  param = NULL,
 *  ssid  = ssid,
 *  psk   = "",
 *  bssid = bssid,
 *  priority = 0
 */
int wpa_manager_configure_bssid_async(wpa_manager_asyc_cb_t cb, void *param, char *ssid, char *psk, char *bssid, int priority)
{
    wpa_manager_t *m = &s_wpa_manager;

	if ((m->started == 0) || (m->ctrl_conn == NULL)) {
		return -1;
	}

    pthread_mutex_lock(&m->op_cond_mutex);

	m->current_op.op = WPA_OP_CONFIGURE_NETWORK;
	m->current_op.func = prv_op_configure_network;
	m->current_op.cb = cb;
	m->current_op.cb_param = param;

    memset(&m->current_op.func_params.configure_network_params, 0, sizeof(configure_network_params_t));
	memcpy(m->current_op.func_params.configure_network_params.psk, psk, strlen(psk));
	if (ssid != NULL) {
		memcpy(m->current_op.func_params.configure_network_params.ssid, ssid, strlen(ssid));
	} else {
		m->current_op.func_params.configure_network_params.ssid[0] = 0;
	}
	if (bssid != NULL) {
		memcpy(m->current_op.func_params.configure_network_params.bssid,
               bssid,
               sizeof(m->current_op.func_params.configure_network_params.bssid));
	} else {
		m->current_op.func_params.configure_network_params.bssid[0] = 0;
	}
	m->current_op.func_params.configure_network_params.priority = priority;
	m->current_op.pending = m->current_op.pending + 1;

	AFLOG_DEBUG1("wpa_manager_configure_bssid_async:: enable pending=%d, op=%d,%s",
				m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);


    pthread_cond_signal(&m->op_cond);
    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_status_async(wpa_manager_asyc_cb_t cb, void *param)
{
    wpa_manager_t *m = &s_wpa_manager;
    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        return -1;
    }

    pthread_mutex_lock(&m->op_cond_mutex);

    m->current_op.op = WPA_OP_STATUS;
    m->current_op.func = prv_op_status;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.pending = m->current_op.pending + 1;
    AFLOG_DEBUG1("wpa_manager_status_async:: enable pending=%d, op=%d,%s",
                 m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_scan_async(wpa_manager_asyc_cb_t cb, void *param)
{
    wpa_manager_t *m = &s_wpa_manager;
    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        return -1;
    }


    pthread_mutex_lock(&m->op_cond_mutex);

    m->current_op.op = WPA_OP_SCAN;
    m->current_op.func = prv_op_scan;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.pending = m->current_op.pending + 1;
    AFLOG_DEBUG1("wpa_manager_scan_async:: enable pending=%d, op=%d, %s",
                 m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_connect_async(wpa_manager_asyc_cb_t cb, void *param, int network_id)
{
    wpa_manager_t *m = &s_wpa_manager;

    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        AFLOG_DEBUG2("wpa_manager_connect_async:: wpa manager not ready !!");
        return -1;
    }

    AFLOG_DEBUG2("wpa_manager_connect_async:: attempt to reconnect to network_id = %d", network_id);
    if (network_id < 0) {
        return 0;
    }

    pthread_mutex_lock(&m->op_cond_mutex);

    m->current_op.op = WPA_OP_CONNECT;
    m->current_op.func = prv_op_connect;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.func_params.connect_params.network_id = network_id;
    m->current_op.pending = m->current_op.pending  + 1;
    AFLOG_DEBUG1("wpa_manager_connect_async:: enable pending=%d, op =%d, %s",
                 m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_reconnect_async(wpa_manager_asyc_cb_t cb, void *param)
{
    wpa_manager_t *m = &s_wpa_manager;

    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        return -1;
    }

    pthread_mutex_lock(&m->op_cond_mutex);

    m->current_op.op = WPA_OP_RECONNECT;
    m->current_op.func = prv_op_reconnect;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.pending = m->current_op.pending  + 1;
    AFLOG_DEBUG1("wpa_manager_reconnect_async:: enable pending=%d, op=%d, %s",
                 m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_disconnect_async(wpa_manager_asyc_cb_t cb, void *param)
{
    wpa_manager_t *m = &s_wpa_manager;

    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        return -1;
    }

    pthread_mutex_lock(&m->op_cond_mutex);

    m->current_op.op = WPA_OP_DISCONNECT;
    m->current_op.func = prv_op_disconnect;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.pending = m->current_op.pending + 1;
    AFLOG_DEBUG1("wpa_manager_disconnect_async:: enable pending=%d, op =%d,%s",
    m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_poll_rssi_async(wpa_manager_asyc_cb_t cb, void *param)
{
    wpa_manager_t *m = &s_wpa_manager;

    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        return -1;
    }

    pthread_mutex_lock(&m->op_cond_mutex);
    m->current_op.op = WPA_OP_DISCONNECT;
    m->current_op.func = prv_op_disconnect;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.pending = m->current_op.pending + 1;
    AFLOG_DEBUG1("wpa_manager_poll_rssi_async:: enabling pending=%d, op=%d,%s",
                m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);


    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}

int wpa_manager_remove_network_async(wpa_manager_asyc_cb_t cb, void *param, int network_id)
{
    wpa_manager_t *m = &s_wpa_manager;

    if ((m->started == 0) || (m->ctrl_conn == NULL)) {
        return -1;
    }

    if (network_id <= 0) {
        return 0;
    }
    AFLOG_DEBUG2("wpa_manager_remove_network:: removing network(id=%d)", network_id);

    pthread_mutex_lock(&m->op_cond_mutex);

    m->current_op.op = WPA_OP_REMOVE_NETWORK;
    m->current_op.func = prv_op_remove_network;
    m->current_op.cb = cb;
    m->current_op.cb_param = param;
    m->current_op.func_params.connect_params.network_id = network_id;
    m->current_op.pending = m->current_op.pending + 1;

    AFLOG_DEBUG1("wpa_manager_remove_network_async:: enable pending=%d, op=%d,%s",
                m->current_op.pending, m->current_op.op, s_wpa_op_names[m->current_op.op]);

    pthread_cond_signal(&m->op_cond);

    pthread_mutex_unlock(&m->op_cond_mutex);

    return 0;
}


int wpa_manager_destroy(void)
{
    wpa_manager_t * m = &s_wpa_manager;


    m->started = 0;
    prv_close_connection();
    s_wpa_client.wpa_event_cb = NULL;
    if (m->tm_event) {
        event_del(m->tm_event);
        event_free(m->tm_event);
    }
    m->tm_event = NULL;

    if (m->rpt_rssi_event) {
        event_del (m->rpt_rssi_event);
        event_free (m->rpt_rssi_event);
    }
    m->rpt_rssi_event = NULL;

    if (m->ctrl_iface_name != NULL) {
        m->ctrl_iface_name = NULL;
    }

    if (m->op_cond_created) {
        pthread_cond_destroy(&m->op_cond);
        m->op_cond_created = 0;
    }

    if (m->op_cond_attr_created) {
        pthread_condattr_destroy(&m->op_cond_attr);
        m->op_cond_attr_created = 0;
    }

    if (m->op_cond_mutex_created) {
        pthread_mutex_destroy(&m->op_cond_mutex);
        m->op_cond_mutex_created = 0;
    }

    if (m->op_thread_created) {
        void *result;
        pthread_cancel(m->op_thread);
        pthread_join(m->op_thread, &result);
        m->op_thread_created = 0;
    }

    m->evbase = NULL;

    // reset the cache ap list
    wifista_reset_ap_list();

    // reset so we can display the warning message
    s_warning_displayed = 0;

    return 0;
}


/**
 * wpa_manager_init
 *
 */
int wpa_manager_init(struct event_base *evbase,
                     wpa_manager_wpa_event_callback_t wpa_event_callback,
                     void *wpa_event_cb_param)
{
    wpa_manager_t *m;
    wpa_client_t  *c;
    int res = -1;


    if (evbase == NULL) {
        AFLOG_ERR("wap_manager_init::Invalid input:evbase=NULL");
        return (res);
    }

    AFLOG_INFO("wpa_manager_init:: Initialize wpa_manager");
    m = &s_wpa_manager;
    memset(m, 0, sizeof(s_wpa_manager));
    c = &s_wpa_client;

    m->evbase = evbase;
    c->wpa_event_cb = wpa_event_callback;


    m->rpt_rssi_event = event_new(m->evbase, -1, (EV_TIMEOUT|EV_PERSIST),
                               wifista_report_rssi_tmout_handler, (void*)m->evbase);
    if (m->rpt_rssi_event == NULL) {
        AFLOG_ERR("wpa_manager_init::failed to create rpt_rssi event");
        goto error;
    }

    if (pthread_condattr_init(&m->op_cond_attr) < 0) {
        AFLOG_ERR("wpa_manager_init:pthread_condattr_init:errno=%d", errno);
        goto error;
    }
    m->op_cond_attr_created = 1;

    if (pthread_cond_init(&m->op_cond, &m->op_cond_attr) < 0) {
        AFLOG_ERR("wpa_manager_init:pthread_cond_init:errno=%d", errno);
        goto error;
    }
    m->op_cond_created = 1;

    if (pthread_mutex_init(&m->op_cond_mutex, NULL) != 0) {
        AFLOG_ERR("wpa_manager_init:pthread_mutex_init:errno=%d", errno);
        goto error;
    }
    m->op_cond_mutex_created = 1;

    // Note: the connection to wpa_supplicant is done in prv_try_connection_cb
    // when this event is handled.
    m->tm_event = event_new(m->evbase, -1, EV_TIMEOUT, prv_try_connection_cb, NULL);
    struct timeval tv = {0, 0};
    res = event_add(m->tm_event, event_base_init_common_timeout(m->evbase, &tv));
    if (res != 0) {
        AFLOG_ERR("wpa_manager_init::failed to create event %d", res);
        goto error;
    }

    if (pthread_create(&m->op_thread, NULL, prv_wpa_worker_loop, NULL) != 0) {
        AFLOG_ERR("wpa_manager_init::failed to create pthread::errno=%d", errno);
        goto error;
    }
    m->op_thread_created = 1;

    // wpa_manager is initialized.
    return 0;

error:
    wpa_manager_destroy();
    return res;
}


/* Wrapper APIs  */
wpa_manager_t *wifista_get_wpa_mgr()
{
    return &s_wpa_manager;
}

void wpa_manager_dump()
{
    wpa_manager_t *m = &s_wpa_manager;

    AFLOG_DEBUG1("s_wpa_manager:");
    AFLOG_DEBUG1("  started=%d", m->started);
    AFLOG_DEBUG2("  evbase=%p",  m->evbase);
    AFLOG_DEBUG2("  tm_event=%p", m->tm_event);
    AFLOG_DEBUG2("  wpa_event=%p", m->wpa_event);
    AFLOG_DEBUG1("  ctrl_iface_name=%s", (m->ctrl_iface_name == NULL) ? "NULL" : m->ctrl_iface_name);
    AFLOG_DEBUG2("  ctrl_conn=%p", m->ctrl_conn);
    AFLOG_DEBUG2("  mon_conn=%p", m->mon_conn);
    AFLOG_DEBUG1("  op_thread_created=%d", m->op_thread_created);
    AFLOG_DEBUG1("  op_cond_attr_created=%d", m->op_cond_attr_created);
    AFLOG_DEBUG1("  op_cond_created=%d", m->op_cond_created);
    AFLOG_DEBUG1("  op_cond_mutex_created=%d", m->op_cond_mutex_created);
    AFLOG_DEBUG1("  current_op: ");
    AFLOG_DEBUG1("      op = %d, %s", m->current_op.op, s_wpa_op_names[m->current_op.op]);
    AFLOG_DEBUG1("      pending = %d", m->current_op.pending);
    AFLOG_DEBUG2("      cb = %p", m->current_op.cb);
    AFLOG_DEBUG2("      cb_param = %p", m->current_op.cb_param);

    AFLOG_DEBUG2("  rpt_rssi_event = %p", m->rpt_rssi_event);

    AFLOG_DEBUG1("  assoc_info:");
    AFLOG_DEBUG1("      associated = %d", m->assoc_info.associated);
    AFLOG_DEBUG1("      network id = %d", m->assoc_info.id);
    AFLOG_DEBUG1("      ssid = %s", m->assoc_info.ssid);
    AFLOG_DEBUG1("      mode = %s", m->assoc_info.mode);
}


/* Get the rssi value of the current connected network */
int wpa_get_conn_network_rssi ()
{
	int32_t rssi;

	/* Note: when no network is connected, wpa_supplicant returns rssi as -9999
	 *
	 * >SIGNAL_POLL
	 * RSSI=-9999
	 * LINKSPEED=0
	 * NOISE=9999
	 * FREQUENCY=0
	 * per discussion: Should report -128 dBm(for all intents and purposes no signal).
	 */
	rssi = prv_get_rssi();
	if (rssi < -128 ) {
		rssi = 0;
	}
	return rssi;
}
