/*
 * wifistad.c
 *
 * The WIFI station daemon (wifistad)
 *
 * The wifistad manages the WPA supplicant.  The wifistad is responsible for
 * starting it up and taking it down, connecting to its socket, controlling
 * which networks to enable, etc.
 *
 * The Wi-Fi station daemon will do a few other things as well:
 *  - Provides SSID list to Hubby for enabling user's AP
 *  - Sets up WPA supplicant config for connecting to user's AP Broadcasts the
 *    Wi-Fi state throughout the connection process so Hubby can pass the
 *    information to the application
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>
#include <syslog.h>
#include <event.h>
#include <event2/thread.h>
#include <time.h>

#include "af_ipc_common.h"
#include "af_ipc_server.h"
#include "af_log.h"
#include "af_attr_client.h"
#include "af_util.h"

#include "common.h"
#include "wpa_manager.h"
#include "wifistad.h"
#include "mac_whitelist.h"
#include "../include/hub_config.h"  // TODO - remove when attrd is ready
#include "wifistad_common.h"


// Note: name need to match attrd ownerhsip
#define WIFISTAD_IPC_SERVER_NAME     "IPC.WIFISTAD"
#define WIFISTAD_MAX_NUM_BSSID       50
#define WIFISTAT_CONN_TMOUT_VAL		 20
#define PERIODIC_TM_VAL     		 20


// extern
extern char *WPA_EVENT_ID_STR[WPA_EVENT_ID_MAX];

extern int8_t cm_is_service_alive(const char *service,
				const char *itf_string,
				uint8_t use_echo);


// IPC server for this daemon
uint8_t				wifista_bootup = 1;
af_ipcs_server_t 	*g_wifi_sta_server = NULL;
uint32_t 			g_debugLevel = 2;


const char *WPA_STATE_STR[WPA_STATE_MAX] = {
	"WPA STATE NOT READY",
	"WPA STATE READY",
	"WPA STATE CONNECTING",
	"WPA STATE CONNECTED",
};


typedef enum {
	WIFISTAD_STATE_UNINITIALIZED,
	WIFISTAD_STATE_SCANNING,
	WIFISTAD_STATE_WPA_CONNECTING,
	WIFISTAD_STATE_WPA_CONNECTED,
	WIFISTAD_STATE_BECOMING_MASTER,
	WIFISTAD_STATE_MASTER_READY,

	WIFISTAD_STATE_MAX
} wifistad_state_t;


const char *WIFISTAD_STATE_STR[] = {
	"UNINITIALIZED",
	"SCANNING",
	"WPA_CONNECTING",
	"WPA_CONNECTED",
	"BECOMING MASTER",
	"MASTER READY",
};

typedef enum {
	WIFISTAD_EVENT_READY= 0,
	WIFISTAD_EVENT_SCAN,
	WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE,
	WIFISTAD_EVENT_WPA_CONNECTING,
	WIFISTAD_EVENT_WPA_CONNECTED,
	WIFISTAD_EVENT_WPA_CONNECTING_TMOUT,
	WIFISTAD_EVENT_WPA_DISCONNECTED,
	WIFISTAD_EVENT_WPA_TERMINATED,
	WIFISTAD_EVENT_HOSTAPD_DISCONNECTED,
	WIFISTAD_EVENT_HOSTAPD_CONNECTED,

	WIFISTAD_EVENT_MAX
} wifistad_event_t;

const char *WIFISTAD_EVENT_STR[WIFISTAD_EVENT_MAX] = {
	"READY",
	"SCAN",
	"SCAN_RESULTS AVAILABLE",
	"WPA_CONNECTING",
	"WPA_CONNECTED",
	"WPA_CONNECTING TMOUT",
	"WPA_DISCONNECTED",
	"WPA_TERMINATED",
	"HOSTAPD DISCONNECTED",
	"HOSTAPD CONNECTED",
};

typedef struct event_desc_s {
	wifistad_event_t event;
	void *param;
} event_desc_t;


// use by event_base_once to queue the event into the main thread
struct timeval zero_timeout = {0, 0};

static uint8_t reconn_count = 1;
static char *scan_results = NULL;
static struct event_base *s_evbase;
static wpa_state_e s_wpa_state = WPA_STATE_NOT_READY;

static void prv_save_scan_results(char *results);
static void prv_scan_started_callback(void *my_param, void *result);
void  wifistad_close ();
void wifistad_attr_on_close(int status, void *context);
static void prv_handle_connecting_tmout (wpa_manager_t *m);
void prv_wpa_event_callback(evutil_socket_t fd, short evts, void *param);
static int prv_set_event(wifistad_event_t event, void *param, struct timeval *timeout);

extern int prv_send_req_ping_networks(void);
extern void wpa_manager_dump();

static uint8_t  s_has_wifi_cfg_info = 0;
// peridic check timer event
static struct event *periodic_chk_ev = NULL;

// to TRack the conn tmout timer
static uint8_t  s_conn_timer_set = 0;
#define TRACK_CONN_TIMER(event)                             \
do {                                                        \
	if (event == WIFISTAD_EVENT_WPA_CONNECTING_TMOUT) { \
		s_conn_timer_set = s_conn_timer_set + 1;    \
		AFLOG_INFO("SET_CONN_TIMER: %d", s_conn_timer_set); \
	}                                                   \
} while (0)

#define EXPIRE_CONN_TIMER(event)                            \
do {                                                        \
	if (event == WIFISTAD_EVENT_WPA_CONNECTING_TMOUT) { \
		if (s_conn_timer_set >= 1) {                \
			s_conn_timer_set = s_conn_timer_set - 1; \
		}                                           \
		else {                                      \
			s_conn_timer_set = 0;               \
		}                                           \
		AFLOG_INFO("EXPIRE_CONN_TIMER: %d", s_conn_timer_set); \
	}                                                   \
} while (0)


struct timespec prv_time_diff(struct timespec start, struct timespec end)
{
    struct timespec temp;

    if ((end.tv_nsec - start.tv_nsec) < 0) {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    } else {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}


// we want to cap the wifi setup to ~1 minute or 60 seconds:
#define CONN_TIMER_CAP      60
static void prv_set_wifi_setup_timer()
{
    static struct timespec start_conn_time;
    struct timeval conn_timeout = {WIFISTAT_CONN_TMOUT_VAL, 0};

    if (s_conn_timer_set == 0) {
        clock_gettime(CLOCK_MONOTONIC, &start_conn_time);
        AFLOG_INFO("prv_set_wifi_setup_timer:: initiate timer for wifi setup");
        prv_set_event(WIFISTAD_EVENT_WPA_CONNECTING_TMOUT, NULL, &conn_timeout);
    }
    else {
        struct timespec diff;
        struct timespec time_now;

        clock_gettime(CLOCK_MONOTONIC, &time_now);
        diff = prv_time_diff(start_conn_time, time_now);
        AFLOG_DEBUG2("prv_set_wifi_setup_timer::end=%ld.%ld, start=%ld.%ld , diff=%ld.%ld",
					time_now.tv_sec, time_now.tv_nsec,
					start_conn_time.tv_sec, start_conn_time.tv_nsec,
					diff.tv_sec, diff.tv_sec);

		// has wifi setup timer being 1 min or 60s?
		// trying best to have the timer: 55s - 75s range
        if ((diff.tv_sec != 0) && (diff.tv_sec < (CONN_TIMER_CAP - 5))) {
            prv_set_event(WIFISTAD_EVENT_WPA_CONNECTING_TMOUT, NULL, &conn_timeout);
        }
    }
}


/* Last step of WIFI setup (if not done, don't call this function)
 *
 * - call after echo alive check to send wifi setup/steady state
 *   attributes updates
 * - perform house cleaning for WIFI setup
 */
static void prv_post_echo_check_processing(uint8_t  echo_succ)
{
	wpa_manager_t *m = wifista_get_wpa_mgr();
	wifi_cred_t   *wCred_p = (wifi_cred_t *)m->wifi_setup.data_p;


	AFLOG_INFO("prv_post_echo_check_processing:: WIFI connected to (%s). Echo %s",
                ((wCred_p == NULL) ? m->assoc_info.ssid : wCred_p->ssid),
				((echo_succ == 1)? "succesful" : "failed") );
	if (echo_succ == 1) {
		// Update the WIFI setup state (to the service)
		m->wifi_setup.setup_state = WIFI_STATE_CONNECTED;
		wifista_setup_send_rsp(&m->wifi_setup);

		// Update WIFI steady state (to the service)
		wifista_set_wifi_steady_state(WIFI_STATE_CONNECTED);
	}
	else {
		// WIFI setup: AP is connected, but echo to service failed
		// Update wifi setup state to the service
		m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_ECHOFAILED;
		wifista_setup_send_rsp(&m->wifi_setup);

		// Update WIFI steady state (to the service)
		wifista_set_wifi_steady_state(WIFI_STATE_ECHOFAILED);
	}

	// Update the configured SSID (to the service)
	af_attr_set(AF_ATTR_WIFISTAD_CONFIGURED_SSID,
                     (uint8_t *)&m->assoc_info.ssid, strlen(m->assoc_info.ssid),
                     wifista_attr_on_set_finished, NULL);

	// delete the previous connected network (from the wpa_supplicant)
	if (m->wifi_setup.prev_network_id > 0) {
		AFLOG_DEBUG1("prv_post_echo_check_processing:: deleting prevous network (id=%d)",
                         m->wifi_setup.prev_network_id);
		wpa_manager_remove_network_async(NULL, NULL, m->wifi_setup.prev_network_id);
	}

	// done with WIFI setup, reset
	AFLOG_DEBUG2("iprv_post_echo_check_processing:: free wifi data, RESET_WIFI_SETUP(m)");
	if (m->wifi_setup.data_p != NULL) {
		free(m->wifi_setup.data_p);
	}
	RESET_WIFI_SETUP(m);

	return;
}


// attempt to connect to wifi with the configured userid/auth
static int prv_attempt_conn_with_config()
{
	int 			rc = -1;
	wifi_cred_t   	*wifi_cred = malloc(sizeof(wifi_cred_t));

	if (wifi_cred == NULL) {
		AFLOG_ERR("prv_attemp_conn_with_config:: malloc failed, errno=%d, %s",
				  errno, strerror(errno));
		return (-1);
	}
	memset(wifi_cred, 0, sizeof(wifi_cred_t));
	if (wifista_read_wifi_cred(wifi_cred) == 1) {
		AFLOG_DEBUG2("prv_attempt_conn_with_config:: previously provisioned - reconnect");
		wifi_cred->prev_provisioned = 1;   // flag to see if we need to save
		wifi_cred->bssid = NULL;

		// update the service with the wifi steady state
		wifista_set_wifi_steady_state(WIFI_STATE_PENDING);

		// connect to the previous AP (with the save credentials) if not connected
		AFLOG_DEBUG2("prv_attempt_conn_with_config:: invoke wpa_manager_status_async");
		wpa_manager_status_async(wifistat_wpa_user_reconn, wifi_cred);

		rc = 1;
		AFLOG_DEBUG1("prv_attempt_conn_with_config:: s_has_wifi_cfg_info = 1");
		s_has_wifi_cfg_info = 1;
	}
	else {
		AFLOG_DEBUG1("prv_attempt_conn_with_config:: s_has_wifi_cfg_info = 0");
		s_has_wifi_cfg_info = 0;
		wpa_manager_status_async(NULL, NULL);

		if (wifi_cred != NULL)
			free(wifi_cred);
		wifi_cred = NULL;
	}
	return (rc);
}

// perodically check to see if wpa_supplicant connection is good
void wpa_periodic_check(evutil_socket_t fd, short what, void *arg)
{
    wpa_manager_t   *m = wifista_get_wpa_mgr();
    uint8_t         wpa_ok = (m->ctrl_conn != NULL);
	static uint8_t  count = 0;


	AFLOG_DEBUG2("wpa_periodic_check::wpa_state=(%d-%s), wpa_ok=%d, assoc ssid:%s, user_request=%d",
				s_wpa_state, WPA_STATE_STR[s_wpa_state], wpa_ok,
				m->assoc_info.ssid,
				(m->wifi_setup.who_init_setup == USER_REQUEST));
	AFLOG_DEBUG2("wpa_periodic_check:: s_has_wifi_cfg_info = %d", s_has_wifi_cfg_info);

	// user just initiated wifi setup. don't interfer with it
	if (m->wifi_setup.who_init_setup == USER_REQUEST) {
		return;
	}

	// if things fail for whatever reason, terminate and re-establish wpa
	// connection
	if (!wpa_ok) {
		if (s_wpa_state != WPA_STATE_NOT_READY) {
			if (s_wpa_state == WPA_STATE_CONNECTING) {
				wifista_wpa_post_event(WPA_EVENT_ID_CFG_CHECK, NULL);
			}
			else {
				AFLOG_INFO("prv_wpa_periodic_check:: failed -> post terminated");
				wifista_wpa_post_event(WPA_EVENT_ID_TERMINATED, NULL);
			}
		}
    }
    else {
		if (m->current_op.pending > 5) { // pending should not be greater than 1
			//hack: in case the worker_loop thread is hang.
			AFLOG_INFO("prv_wpa_periodic_check:: work thread hangs -> post terminated");
			wpa_manager_dump(); // debug info
			wifista_wpa_post_event(WPA_EVENT_ID_TERMINATED, NULL);
		}
		else if ((s_wpa_state == WPA_STATE_READY) || (s_wpa_state == WPA_STATE_CONNECTING)) {
			count++;
			if ((count % 10) == 0) {
				AFLOG_DEBUG1("prv_wpa_periodic_check:: not connect -> post CFG_CHECK, count=%d",
				             count);
				count = 0;
			}
			wifista_wpa_post_event(WPA_EVENT_ID_CFG_CHECK, NULL);
		}
    }

    return;
}



// events = EV_TIMEOUT
static void prv_state_machine(evutil_socket_t fd, short events, void *param)
{
	static wifistad_state_t state = WIFISTAD_STATE_UNINITIALIZED;
	event_desc_t 		*event_desc = (event_desc_t *)param;
	wifistad_event_t 	event;


	AFLOG_INFO("prv_state_machine:: events=%d param=%p ", events, param);
	if ((param == NULL) || (event_desc->event > WIFISTAD_EVENT_MAX)) {
		AFLOG_ERR("prv_state_machine:: invalid input");
		return;
	}

	event = event_desc->event;
	wpa_manager_t *m = wifista_get_wpa_mgr();

	AFLOG_INFO("> STATE (%d - %s) EVENT (%d - %s)",
			   state, WIFISTAD_STATE_STR[state],
			   event, WIFISTAD_EVENT_STR[event]);

	EXPIRE_CONN_TIMER(event);

	switch (state) {
		case WIFISTAD_STATE_UNINITIALIZED:
			switch (event) {
				case WIFISTAD_EVENT_READY: {
					// We entering SCANNING state, but disable AUTO. So, scanning only
					// commences when the user request for it.
					state = WIFISTAD_STATE_SCANNING;
					AFLOG_DEBUG2("prv_state_machine: reset_wifi_setup");
					RESET_WIFI_SETUP(m);

					/* different scenarios:
					 * reboot - we would want to reconnect via user provisioned data.
					 * restart - wifi should be already connected and association
					 * should be in place.  No need to reconnect.
					 **/
                    if (prv_attempt_conn_with_config() > 0) {
						state = WIFISTAD_STATE_WPA_CONNECTING;
					}
					else {
						wifista_set_wifi_steady_state(WIFI_STATE_NOTCONNECTED);
						m->wifi_setup.setup_state = WIFI_STATE_NOTCONNECTED;
					}
				}
				break;

				case WIFISTAD_EVENT_SCAN: {
					AFLOG_INFO("prv_state_machine::CANNOT SCAN, not ready");
					if (WIFI_SETUP_IS_USER_REQUESTED(m))  {
						wifista_reset_ap_list();

						// tell the app that scan request failed.
						wifista_setup_send_rsp(&m->wifi_setup);
					}
				}
				break;

				default:
					break;
			}
			break;


		case WIFISTAD_STATE_SCANNING:
			if (event == WIFISTAD_EVENT_SCAN) {
				AFLOG_INFO("prv_state_machine::%s initiates the scanning process",
						   (m->wifi_setup.who_init_setup == USER_REQUEST) ? "USER":"SYS");
				wpa_manager_scan_async(prv_scan_started_callback, NULL);
			}
			else if (event == WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE) {
				AFLOG_DEBUG3("prv_state_machine:: attempt to connect, scan_results = %p,(%s)",
					   scan_results, (scan_results == NULL) ? "NULL" : scan_results);
				wifista_wpa_process_scan_results(s_wpa_state, scan_results);
			}
			else if (event == WIFISTAD_EVENT_WPA_CONNECTED) {
				state = WIFISTAD_STATE_WPA_CONNECTED;
			}
			else if (event == WIFISTAD_EVENT_WPA_CONNECTING) {
				state = WIFISTAD_STATE_WPA_CONNECTING;
			}
			break;


		case WIFISTAD_STATE_WPA_CONNECTING:
			switch (event) {
				case WIFISTAD_EVENT_WPA_CONNECTED:
					state = WIFISTAD_STATE_WPA_CONNECTED;
					break;

				case WIFISTAD_EVENT_SCAN: {  /* conn possible failed, go back to scanning state */
					state = WIFISTAD_STATE_SCANNING;
				}
				break;

				case WIFISTAD_EVENT_WPA_CONNECTING_TMOUT:
					if (s_conn_timer_set == 0) {
						state = WIFISTAD_STATE_SCANNING;
						prv_handle_connecting_tmout(m);
					}
					break;

				case WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE:
					if (m->wifi_setup.setup_event == WPA_EVENT_ID_WIFI_SCAN_REQUESTED) {
						wifista_wpa_process_scan_results(s_wpa_state, scan_results);
					}
					break;

				default:
					break;
			}
			break;


		case WIFISTAD_STATE_WPA_CONNECTED:
			/* connection achieve.  reset wifi setup */
			switch (event) {
				case WIFISTAD_EVENT_WPA_DISCONNECTED:
					// go to scanning state -- TODO: anything to reset
					state = WIFISTAD_STATE_SCANNING;
					break;

				case WIFISTAD_EVENT_SCAN:
					AFLOG_INFO("prv_state_machine::%s initiate the scanning process",
							   (m->wifi_setup.who_init_setup == USER_REQUEST) ? "USER":"SYS");
					wpa_manager_scan_async(prv_scan_started_callback, NULL);
					break;

				case WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE:
					wifista_wpa_process_scan_results(s_wpa_state, scan_results);
					break;

				case WIFISTAD_EVENT_WPA_CONNECTING_TMOUT:
					if (s_conn_timer_set > 0) { // wait until it is zero
						break;
					}
					wpa_manager_status_async(NULL, NULL);

					AFLOG_DEBUG2("prv_state_machine:: event=CONNECTING_TMOUT, setup_state=%d, who_init=%d",
								m->wifi_setup.setup_state, m->wifi_setup.who_init_setup);

					if (m->wifi_setup.setup_state == WIFI_STATE_ECHOFAILED) {
						int8_t   echo_succ = 0;
						//wifi_cred_t * wCred_p = (wifi_cred_t *)m->wifi_setup.data_p;

						echo_succ = cm_is_service_alive(echo_service_host_p, m->ctrl_iface_name, 1);
						prv_post_echo_check_processing(echo_succ);
					}
					break;

				default:
					break;
			}
			break;

		default:
			AFLOG_INFO("prv_state_machine:: unsupport state=%d", state);
			break;
	}

	// independent of the state -- we lost wifi
	if ((event == WIFISTAD_EVENT_WPA_TERMINATED) && (state != WIFISTAD_STATE_UNINITIALIZED)) {
		state = WIFISTAD_STATE_UNINITIALIZED;
		AFLOG_INFO("WIFISTAD:: Connection to wpa_supplicant lost - trying to reconnect");

		if (s_wpa_state == WPA_STATE_NOT_READY) { // wpa is not doing anything
			wpa_manager_destroy();
			s_conn_timer_set = 0;    // reset tmout timer count
			wifista_bootup   = 1;    // restart wpa

			if (wpa_manager_init(s_evbase, NULL, NULL) < 0) {
				AFLOG_ERR("wifistad::wpa_manager_init: failed.  Exit");
				wifistad_close ();
				exit(EXIT_SUCCESS);
			}
		}
	}

	free(event_desc);

	AFLOG_INFO("< STATE = (%d, %s)", state, WIFISTAD_STATE_STR[state]);
}


/* prv_set_event
 *
 * Set event of wifistad_event_t for wifistad.  The event is handled in prv_state_machine
 */
static int prv_set_event(wifistad_event_t event, void *param, struct timeval *timeout)
{
	event_desc_t *event_desc = malloc(sizeof(*event_desc));


	AFLOG_INFO("prv_set_event:: Setting "
				"event=%d(%s), s_evbase=%p, event_desc=%p",
			   event, WIFISTAD_EVENT_STR[event], s_evbase, event_desc);

	if (event_desc == NULL) {
		AFLOG_ERR("prv_set_event:malloc failed");
		return -1;
	}
	if (timeout == NULL) {
		AFLOG_ERR("prv_set_event: timeout invalid");
		return (-1);
	}
	AFLOG_INFO("prv_set_event:: event timeout: %ld.%06ld ", timeout->tv_sec, timeout->tv_usec);

	TRACK_CONN_TIMER(event);

	event_desc->event = event;
	event_desc->param = param;

	return event_base_once(s_evbase, -1, EV_TIMEOUT, prv_state_machine, (void *)event_desc, timeout);
}


// handle connecting tmout
static void prv_handle_connecting_tmout (wpa_manager_t *m)
{
	if (m == NULL)
		return;


	AFLOG_DEBUG2("prv_handle_connecting_tmout:: EVENT_WPA_CONNECTING_TMOUT, revert to network=%d",
		m->wifi_setup.prev_network_id);
	int prev_network_id = m->wifi_setup.prev_network_id;

	// delete the "unsuccessful network"
	// wpa_manager_disconnect_async(NULL, NULL);
	wpa_manager_remove_network_async(NULL, NULL, m->wifi_setup.network_id);

	// inform service and APP wifi_setup failed
	AFLOG_DEBUG2("prv_handle_connecting_tmout:: Wifi setup failed (state=%d), RESET_WIFI_SETUP(m)",
		m->wifi_setup.setup_state);
	if (m->wifi_setup.setup_state == WIFI_STATE_PENDING) {
		m->wifi_setup.setup_state = WIFI_STATE_ASSOCATIONFAILED;
	}
	wifista_setup_send_rsp(&m->wifi_setup);

	if (m->wifi_setup.data_p != NULL) {
		free(m->wifi_setup.data_p);
	}
	RESET_WIFI_SETUP(m);

	// try to reconnecting back to previous one
	// possible scenario: At reboot or daemon restart, connect failed, but no previous network id
	if (prev_network_id > 0) {
		wpa_manager_connect_async(NULL, NULL, prev_network_id);
	}
	else {
		wifista_wpa_post_event(WPA_EVENT_ID_CFG_CHECK, NULL);
	}
	return;
}


//static void prv_get_next_master(char **bssid, char **ssid)
uint8_t prv_get_next_master(char **bssid, wifista_ap_t *ap, uint8_t *is_more)
{
	static char *line1 = NULL;
	char *line2;
	static char *saveptr1;
	static char *saveptr2;

	*bssid = NULL;
	*is_more = 1;

	if (ap == NULL) {
		AFLOG_ERR("prv_get_next_master:: invalid input");
		return (-1);
	}

	/* tokenize into lines and parse */
	if (line1 == NULL) {
		line1 = strtok_r(scan_results, "\n", &saveptr1);
	}

	while (1) {
		/* get line */
		line1 = strtok_r(NULL, "\n", &saveptr1);

		if (line1 == NULL) {
			free(scan_results);
			scan_results = NULL;

			AFLOG_DEBUG3("get_next_master:: is_more = 0");
			*is_more = 0;
			return (-1);
		}
		AFLOG_DEBUG3("get_next_master:: %s", line1);

		char *tok[5];
		int i;
		line2 = line1;
		for (i = 0; i < 5; i++, line2 = NULL) {
			tok[i] = strtok_r(line2, "\t", &saveptr2);
		}


		// filter out AP with \x00 (which is NULL)
		if ((tok[4] != NULL) &&
			(strncmp(tok[4], "\\x00", 4) != 0)) {
			uint8_t   ssid_len = 0;

			// truncate the ssid length if longer than 32
			*bssid = tok[0];
			ssid_len = strlen(tok[4]);
			if (ssid_len > WIFISTA_SSID_LEN) {
				return (-1);
			}

			strncpy(ap->ssid, tok[4], ssid_len);
			ap->rssi = atoi(tok[2]);
			ap->support_security = wifista_is_AP_support_sec(tok[3]);

			// have good data
			return (0);
		}
	}

	*is_more = 0;
    return (-1);
}


static void prv_scan_started_callback(void *my_param, void *result)
{

	if ((int)result < 0) {
		AFLOG_DEBUG3("SCAN FAILED \n");
		// TODO -- if scan has not started, we might want to try to initiate scan again?
		return;
	}
}


/* save the wpa scan results to a global storage.
 * Note: the memory is released after the scan_results is processed.
 */
static void prv_save_scan_results(char *results)
{
	if (results != NULL) {
		/* gotta get this off the wpa_manager context */
		if (scan_results == NULL) {
			scan_results = strdup(results);
		}
	}
	else {
		AFLOG_WARNING("prv_save_scan_result:: no results");
	}
	return;
}


/* prv_wpa_event_callback
 *
 * Process wpa related events
 */
//static void prv_wpa_event_callback(wpa_event_t *event)
void prv_wpa_event_callback(evutil_socket_t fd, short evts, void *param)
{
	wpa_manager_t *m = wifista_get_wpa_mgr();
	wpa_event_t *event = (wpa_event_t *)param;


	if (event == NULL) {
		AFLOG_ERR("prv_wpa_event_callback:: invalid input");
		return;
	}
	if (event->id >= WPA_EVENT_ID_MAX) {
		goto EV_CALLBACK_DONE;
	}

	AFLOG_DEBUG1("prv_wpa_event_callback:: > state=(%d, %s)  event->id=(%d, %s)",
		   s_wpa_state, WPA_STATE_STR[s_wpa_state], event->id, WPA_EVENT_ID_STR[event->id]);

	switch(event->id) {
		case WPA_EVENT_ID_CONNECTED: {
			wifi_cred_t   *wCred_p  = (wifi_cred_t *)m->wifi_setup.data_p;
			uint8_t       echo_succ = 0;
			int8_t        netid = (int)event->result;


			if (s_wpa_state == WPA_STATE_NOT_READY) { // do nothing
				break;
			}

			wpa_manager_status_async(NULL, NULL);

			AFLOG_DEBUG2("prv_wpa_event_callback::WPA_EVENT_ID_CONNECTED network_id=%d \n", netid);
			if ((s_wpa_state == WPA_STATE_CONNECTED) &&
				(m->assoc_info.id == netid) && (m->wifi_setup.who_init_setup != USER_REQUEST)) {
				// we are already in connected state, do nothing.
				AFLOG_DEBUG3("prv_wpa_event_callback:: ALREADY IN CONNECTED STATE, do nothing \n");
				return;
			}

			/* the WPA is connected to the AP*/
			s_wpa_state = WPA_STATE_CONNECTED;

			/* update the states */
			prv_set_event(WIFISTAD_EVENT_WPA_CONNECTED, (void *)1 /*done*/, &zero_timeout);

            /* we need to save the connect info */
			if ((wCred_p) && (wCred_p->prev_provisioned == 0)) {
				wifista_save_wifi_cred(wCred_p);

				AFLOG_DEBUG1("prv_wpa_event_callback:: s_has_wifi_cfg_info = 1");
				s_has_wifi_cfg_info = 1;
			}
			/* script file to execute when wifi associated */
			if (file_exists(WIFI_EVENT_SH_FILE)) {
				AFLOG_INFO("wifistad:: exec %s ", WIFI_EVENT_SH_FILE);

				af_util_system("%s %s", WIFI_EVENT_SH_FILE, "connected");
			}


			echo_succ = cm_is_service_alive(echo_service_host_p, m->ctrl_iface_name, 1);
			if (echo_succ == 1) {
				m->wifi_setup.network_id = netid;
				prv_post_echo_check_processing(1);
			} else { //echo failed. Let's wait until tmout before sending the state to APP
				AFLOG_INFO("prv_wpa_event_callback::Echo failed, delay sending setup. Wait for tmout");
				m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_ECHOFAILED;
			}

            /* give some extra time to handle all the event and time to process echo */
            prv_set_wifi_setup_timer();
		}
		break;


		case WPA_EVENT_ID_DISCONNECTED:
			if (s_wpa_state != WPA_STATE_NOT_READY) {
				s_wpa_state = WPA_STATE_READY;
				wpa_manager_status_async(NULL, NULL);
				wifista_set_wifi_steady_state(WIFI_STATE_NOTCONNECTED);
				prv_set_event(WIFISTAD_EVENT_WPA_DISCONNECTED, (void *)0 /*?*/, &zero_timeout);

				if (file_exists(WIFI_EVENT_SH_FILE)) {
					AFLOG_INFO("wifistad:: exec %s  disconnected", WIFI_EVENT_SH_FILE);
					af_util_system("%s %s", WIFI_EVENT_SH_FILE, "disconnected");
				}
			}
			break;


		case WPA_EVENT_ID_SCAN_RESULTS: {
			// scan in the background, but we just ignore the result if no one is asking for
			// it or while we are in the middle of connecting
			if ((m->wifi_setup.who_init_setup != INIT_NONE) &&
				(m->wifi_setup.setup_event != WPA_EVENT_ID_WIFI_CREDENTIALS)) {
				AFLOG_DEBUG3("prv_wpa_event_callback:: save scan result");

				// we got the scan results back - two options:
				// 	1) auto_connect
				//	2) user wifi setup
				prv_save_scan_results((char *)event->result);
				prv_set_event(WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE, NULL, &zero_timeout);
			}
		}
		break;


		case WPA_EVENT_ID_READY: {
			uint8_t  len;

			if (s_wpa_state == WPA_STATE_NOT_READY) {
				s_wpa_state = WPA_STATE_READY;

				// give the wpa supplicant time to get ready
				wpa_manager_status_async(NULL, NULL);
#if 0
// HOSTAPD not support now
				if (s_hostapd_state != HOSTAPD_STATE_NOT_READY) {
					prv_set_event(WIFISTAD_EVENT_READY, NULL, &zero_timeout);
				}
#endif
				prv_set_event(WIFISTAD_EVENT_READY, NULL, &zero_timeout);
			}

			wifista_set_wifi_steady_state(WIFI_STATE_NOTCONNECTED);
			len = strlen(m->assoc_info.ssid);
			af_attr_set (AF_ATTR_WIFISTAD_CONFIGURED_SSID,
					((len == 0) ? (uint8_t *)" " : (uint8_t *)&m->assoc_info.ssid),
					((len == 0) ? 1 : len),
					wifista_attr_on_set_finished, NULL);

		}
		break;


		case WPA_EVENT_ID_WIFI_SCAN_REQUESTED: {  // user requested scan
			if (s_wpa_state == WPA_STATE_NOT_READY) {
				// we are not able to continue wifi setup when wpa_supplicant
				// is not ready, send zero item
				wifista_reset_ap_list();
				wifista_setup_send_rsp(&m->wifi_setup);
			} else {
				wpa_manager_status_async(NULL, NULL);

				AFLOG_DEBUG2("prv_wpa_event_callback:: SCAN request, start scan");
				WIFI_SETUP_SCAN_REQUEST(m);
				prv_set_event(WIFISTAD_EVENT_SCAN, NULL, &zero_timeout);
			}
		}
		break;


		case WPA_EVENT_ID_CONNECTING: {  // start connecting
			static uint8_t wait_for_tmout = 0;
			int cResult = (int) (event->result);  // conn result

			if (s_wpa_state == WPA_STATE_NOT_READY) {  // do nothing
				break;
			}

			AFLOG_INFO("prv_wpa_event_callback:: connect result=%d, assoc_id=%d, who_init=%d",
					   cResult, m->assoc_info.id, m->wifi_setup.who_init_setup);

			// if we are in the connecting state, and we get another event saying
			// we are trying to connect.  Let it be, and do thing.
			if (cResult < WPA_CONN_RESULT_INIT) {  // something went wrong
				s_wpa_state = WPA_STATE_READY;

				wait_for_tmout = 0;
				if (cResult == WPA_CONN_RESULT_ASS_REJECT) {
					m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_ASSOCATIONFAILED;
					wait_for_tmout = 1;
				}
				else if (cResult == WPA_CONN_RESULT_HANDSHAKE_FAILED) {
					m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_HANDSHAKEFAILED;
					wait_for_tmout = 1;
				}
				else if (cResult == WPA_CONN_RESULT_INVALID_SSID) {
					m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_SSID_NOT_FOUND;
				}
				else if (cResult == WPA_CONN_RESULT_SET_PSK_FAILED) {
					m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_HANDSHAKEFAILED;
				}
				else if (cResult == WPA_CONN_RESULT_TEMP_DISABLED) {
					// when association is temporarily disabled, we should already know
					// the reason: such as handshake failed, or ass_reject etc.
					// Typically, WPA supplicant attempts 3 connect and each attempt has
					//  3 tries of association before it TEMP_DSIABLE -> so let's wait until
					// it is done all the attempts to connect.
					wait_for_tmout = 1;
				}
				else {
					m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_UNKNOWN;
				}

				/* If all the user specified wifi config inputs are valid, then we need to wait until
				 * all attempts to associate completed before we can delete the network
				 */
				if (!wait_for_tmout) {
					// delete the "unsuccessful network from add_network command" if it is not deleted
					wpa_manager_remove_network_async(NULL, NULL, m->wifi_setup.network_id);

					// remember the network id or err code.  Notify service/APP and clean up
					wifista_setup_send_rsp(&m->wifi_setup);
					if (m->wifi_setup.data_p != NULL) {
						free(m->wifi_setup.data_p);
						m->wifi_setup.data_p = NULL;
					}
					AFLOG_INFO("prv_wpa_event_callback:: Done - RESET_WIFI_SETUP");
					RESET_WIFI_SETUP(m);

					/* failed, revert to previous network */
					if (m->assoc_info.id > 0) {
						AFLOG_INFO("prv_wpa_event_callback:: reconnect to network (id=%d, ssid=%s)",
								   m->assoc_info.id, m->assoc_info.ssid);
						wpa_manager_connect_async(NULL, NULL, m->assoc_info.id);
					}
					// let's go back to scanning state
					prv_set_event(WIFISTAD_EVENT_SCAN, NULL, &zero_timeout);
				}
				else {
					if (cResult == WPA_CONN_RESULT_TEMP_DISABLED) {
						AFLOG_INFO("prv_wpa_event_callback:: TEMP_DISABLED, start TMOUT timer");
						prv_set_wifi_setup_timer();
					}
				}
			}
			else {  // connecting seems to be OK
				prv_set_event(WIFISTAD_EVENT_WPA_CONNECTING, NULL, &zero_timeout);

				if (cResult > 0) {
					AFLOG_INFO("prv_wpa_event_callback::connecting, id=%d, start TMOUT timer", cResult);
					m->wifi_setup.network_id = cResult;  // store the add_network id
					prv_set_wifi_setup_timer();

					if (m->wifi_setup.setup_state != WIFI_STATE_PENDING) {
						m->wifi_steady_state = m->wifi_setup.setup_state = WIFI_STATE_PENDING;
						wifista_setup_send_rsp(&m->wifi_setup);
					}
				}

				/* we go to a connecting state, and waited for the wpa's connected event
				 * if no connected event - we wait util the timeout and then check */
				s_wpa_state = WPA_STATE_CONNECTING;
			}
		}
		break;

		case WPA_EVENT_ID_WIFI_CREDENTIALS: {
			/* we have received the wifi credentials from the user
			 * let's initiate configuration of the network
			 */
			wifi_cred_t    *wCred_p = (wifi_cred_t *)event->result;

			if (wCred_p == NULL) {
				AFLOG_ERR("prv_wpa_event_callback:: credential malloc failed, errno=(%d, %s)",
						  errno, strerror(errno));
				UPDATE_WIFI_SETUP_STATE(m, WIFI_STATE_UNKNOWN, WPA_CONN_RESULT_NO_ID);
				wifista_setup_send_rsp(&m->wifi_setup);
				break;
			}

			if ((s_wpa_state == WPA_STATE_CONNECTING) ||
				(s_wpa_state == WPA_STATE_READY) ) {
					wifista_wpa_user_connect_AP(wCred_p, (void *)0);
			}
			else if (s_wpa_state == WPA_STATE_CONNECTED) {
				/* Currently connected to an AP already.  Disconnect first.
				 * When finishing disconnect, try to connect to the user's AP */
				AFLOG_INFO("prv_wpa_event_callback:: Disconnecting AP=%s, Connecting AP=%s",
							   m->assoc_info.ssid, wCred_p->ssid);
				wpa_manager_disconnect_async(wifista_wpa_user_connect_AP, (void *) wCred_p);
			}
			else {
				AFLOG_ERR("prv_wpa_event_callback:: Config WIFI failed, reason=bad state:(%d, %s)",
						 	s_wpa_state, WPA_STATE_STR[s_wpa_state]);

				UPDATE_WIFI_SETUP_STATE(m, WIFI_STATE_UNKNOWN, WPA_CONN_RESULT_NO_ID);
				wifista_setup_send_rsp(&m->wifi_setup);

				free(wCred_p);
				wCred_p = NULL;
			}
		}
		break;


		case WPA_EVENT_ID_TERMINATED: {
				// handle case equivalence to "wifi down"
				s_wpa_state = WPA_STATE_NOT_READY;
				m->started = 0;   // indicate the wpa_manager is going down
				if (m->wifi_setup.who_init_setup == USER_REQUEST) {
					m->wifi_setup.setup_state = WIFI_STATE_NOTCONNECTED;
					af_attr_set(AF_ATTR_WIFISTAD_WIFI_SETUP_STATE,
								(uint8_t *)&m->wifi_setup.setup_state, sizeof(wifi_setup_state_e),
								wifista_attr_on_set_finished, NULL);
				}
				else {
					wifista_set_wifi_steady_state(WIFI_STATE_NOTCONNECTED);
				}
				AFLOG_DEBUG2("prv_pwa_event_callback:: RESET_WIFI_SETUP(m)");
				RESET_WIFI_SETUP(m);
				memset(&m->assoc_info, 0, sizeof(wpa_sta_assoc_t));

				prv_set_event(WIFISTAD_EVENT_WPA_TERMINATED, NULL, &zero_timeout);
			}
			break;


		case WPA_EVENT_ID_CFG_CHECK: {
				if ((s_wpa_state == WPA_STATE_READY) || (s_wpa_state == WPA_STATE_CONNECTING)) {
					AFLOG_INFO("prv_wpa_periodic_check:: s_conn_timer_set=%d, s_has_wifi_cfg_info=%d",
								s_conn_timer_set, s_has_wifi_cfg_info);
					if ((s_conn_timer_set == 0) && (s_has_wifi_cfg_info)) {
						AFLOG_INFO("prv_wpa_periodic_check:: NOT_CONNECTED but configured. Re-try");
						prv_attempt_conn_with_config();
					}
				}
			}
			break;


		default:
			AFLOG_ERR("Unknown/not handled wpa event %d", (wpa_event_id_e)event->id);
			break;
	}

	AFLOG_DEBUG1("prv_wpa_event_callback:: < state=(%d, %s)", s_wpa_state, WPA_STATE_STR[s_wpa_state]);


EV_CALLBACK_DONE:
		if(event) {
			free(event);
		}
}


// express interested to attribute daemon that we are interested in the
// notification for the following attributes.
af_attr_range_t  wifistad_attr_range[3] = {
		{AF_ATTR_ATTRD_REPORT_RSSI_CHANGES, AF_ATTR_ATTRD_REPORT_RSSI_CHANGES},
		{AF_ATTR_CONNMGR_NETWORK_TYPE, AF_ATTR_CONNMGR_NETWORK_TYPE},
		{AF_ATTR_HUBBY_COMMAND, AF_ATTR_HUBBY_COMMAND},
};
#define	WIFISTAD_NUM_ATTR_RANGE   ARRAY_SIZE(wifistad_attr_range)


int32_t wifistad_conn_to_attrd(struct event_base *s_evbase)
{
	int err;

	// connect to communicate with attrd
	err = af_attr_open(s_evbase, WIFISTAD_IPC_SERVER_NAME,
                       WIFISTAD_NUM_ATTR_RANGE, &wifistad_attr_range[0],
                       wifistad_attr_on_notify,      // notify callback
                       wifistad_attr_on_owner_set,   // owner set callback
                       wifistad_attr_on_get_request, // owner get callback
                       wifistad_attr_on_close,       // close callback
                       wifistad_attr_on_open,        // open callback
                       NULL);                        // context
	if (err != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("wifistad::Unable to init the server, err=%d", err);
		return (-1);
	}
	return (0);
}

/****************
 *
 * wifistad main
 *
 ***************/
int main()
{
	struct timeval periodic_tmout_ms = {PERIODIC_TM_VAL, 0};
	int32_t  result;

	openlog("wifistad", LOG_PID, LOG_USER);

	// initialize the MAC whitelist data structures.
	wifistad_init_mac_wl();

	// TODO - remove later when attrd is ready
	hub_config_service_env_init();

	// if the wifi config file exists, then we have the cfg info
	s_has_wifi_cfg_info = file_exists(AFERO_WIFI_FILE);
	AFLOG_DEBUG1("wifistad:: s_has_wifi_cfg_info=%d", s_has_wifi_cfg_info);

	result = evthread_use_pthreads();
	if (result != 0) {
		AFLOG_ERR("wifistad:: error evthread_use_pthreads() call %d", result);
	} else {
		AFLOG_INFO("wifistad:: using multi-threaded libevent");
	}

	// Don't use cached time because of HUB-583
	struct event_config *cfg = NULL;
	cfg = event_config_new();
	if (cfg == NULL) {
		AFLOG_ERR("wifistad:: event_config_new failed");
		return (-1);
	}

	event_config_set_flag(cfg, EVENT_BASE_FLAG_NO_CACHE_TIME);

	s_evbase = event_base_new_with_config(cfg);
	event_config_free(cfg);
	if (s_evbase == NULL) {
		AFLOG_ERR("wifistad::Unable to create s_evbase");
		return (-1);
	}

	{ // setting up the special zero_timeout
		struct timeval tv_in = { 0, 0 };
		const struct timeval *tv_out;
		tv_out = event_base_init_common_timeout(s_evbase, &tv_in);
		memcpy(&zero_timeout, tv_out, sizeof(struct timeval));
	}

	if (wpa_manager_init(s_evbase, NULL, NULL) < 0) {
		AFLOG_ERR("wifistad::wpa_manager_init: failed");
		goto wifistad_exit;
	}

	periodic_chk_ev = event_new(s_evbase, -1, (EV_TIMEOUT|EV_PERSIST), wpa_periodic_check, NULL);
	if (periodic_chk_ev == NULL) {
		AFLOG_ERR("wifistad:: create periodic_chk_ev failed.");
		goto wifistad_exit;
	}
	event_add(periodic_chk_ev, &periodic_tmout_ms);

	// This should be the last
	if (wifistad_conn_to_attrd(s_evbase) < 0) {
		goto wifistad_exit;
	}


#if 0
// NOT support now
	if (hostapd_manager_init(s_evbase, prv_hostapd_event_callback, NULL)) {
		AFLOG_ERR("wifistad::hostapd_manager_init: failed");
		goto wifistad_exit;
	}
#endif

	// Start the event loop
	AFLOG_INFO("wifistad:: running");
	if (event_base_dispatch(s_evbase)) {
		AFLOG_ERR("wifistad::Error running event loop");
	}


wifistad_exit:       /* clean up */
	wifistad_close ();
	return 0;
}


/* wrapper function to close things up for wifistad */
void  wifistad_close ()
{
	AFLOG_INFO("wifistad::Service is shutting down");
	wpa_manager_destroy();

//	hostapd_manager_destroy();

	af_attr_close();

	if (s_evbase) {
		event_base_free(s_evbase);
		s_evbase = NULL;
	}

	// this can still have memory allocate. if so, free it.
	if (scan_results != NULL) {
		free(scan_results);
		scan_results = NULL;
	}

	if (periodic_chk_ev != NULL) {
		event_del (periodic_chk_ev);
		event_free (periodic_chk_ev);
	}

	closelog();
}


/* wifistad_reconn_to_attrd
 *  - attempt to reconnect to attrd after a waiting period.  The waiting
 *  period starts with 1 second, and it increments a second for every
 *  attempts. The waiting period restart at 1 second after it reaches
 *  30 seconds.
 */
void wifistad_reconn_to_attrd(evutil_socket_t fd, short events, void *arg)
{
	int rc = -1;
	struct event_base *base = (struct event_base *)arg;

	if (base) {
		AFLOG_INFO("wifistad_reconn_to_attrd:: reconnecting after %d seconds", reconn_count);
		rc = wifistad_conn_to_attrd(base);
		if (rc < 0) {
			reconn_count++;
			wifistad_attr_on_close(AF_ATTR_STATUS_OK, NULL);
		}
		else {
			reconn_count = 1;
		}

		// when it reaches 30sec , restart the count again.
		if ((reconn_count % 30) == 0) {
			reconn_count = 1;
		}
	}
	else {
		AFLOG_ERR("wifistad_reconn_to_attrd:: event_base went bonkers.exit");

		wifistad_close();
		exit(-1);
	}
}


// wifistad_attr_on_close
//
// When the attrd daemon closed, wifistad as a client, closed too.
// However, the wifistad needs to connect to attrd in order to
// work properly (i.e wifi setup functionality). So, after attrd
// is closed, we will attemtp to reconnect back to it.
//
void wifistad_attr_on_close(int status, void *context)
{
	struct timeval attr_tmout = {(1 * reconn_count), 0};

	AFLOG_INFO("wifistad_attr_on_close:: IPC connection to ATTRD closed");
	if (s_evbase) {
	    event_base_once(s_evbase, -1, EV_TIMEOUT, wifistad_reconn_to_attrd, (void *)s_evbase, &attr_tmout);
	}
}


/* file_exists
 *     Check to see if the file exists.
 *
 * return
 *  1 - file exists
 *  0 - file does NOT exist
 */
int8_t file_exists(const char *filename)
{
    if (filename != NULL) {
        if (access(filename, R_OK ) != -1 ) {
            // file exists
            return (1);
        }
    }
    return (0);
}


/* set the s_has_wifi_cfg_info */
void wifistad_set_wifi_cfg_info(uint8_t has_cfg)
{
	s_has_wifi_cfg_info = has_cfg;
}

