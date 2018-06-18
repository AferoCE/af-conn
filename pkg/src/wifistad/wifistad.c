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
#include "../include/hub_config.h"
#include "wifistad_common.h"
#define NETIF_NAMES_ALLOCATE
#include "../include/netif_names.h"
#include "../include/netcheck_async.h"


// Note: name need to match attrd ownership
#define WIFISTAD_IPC_SERVER_NAME	"IPC.WIFISTAD"
#define WIFISTAD_MAX_NUM_BSSID		50
#define PERIODIC_TIMER_PERIOD_SEC	20
#define ECHO_CHECK_TIMEOUT_MS		20000
#define NETCHECK_DELAY_INITIAL_SEC	2
#define NETCHECK_DELAY_MULTIPLIER	2
#define NETCHECK_DELAY_CAP			20


// extern
extern char *WPA_EVENT_ID_STR[WPA_EVENT_ID_MAX];

// IPC server for this daemon
uint8_t				wifista_bootup = 1;
af_ipcs_server_t	*g_wifi_sta_server = NULL;

#ifdef BUILD_TARGET_DEBUG
uint32_t			g_debugLevel = LOG_DEBUG1;
#else
uint32_t			g_debugLevel = 0;
#endif

/* This enum captures the state of the supplicant */
typedef enum {
	WPA_STATE_NOT_READY,
	WPA_STATE_READY,
	WPA_STATE_CONNECTING,
	WPA_STATE_CONNECTED,
	WPA_STATE_MAX
} wpa_state_t;

const char *WPA_STATE_STR[] = {
	"WPA_STATE_NOT_READY",
	"WPA_STATE_READY",
	"WPA_STATE_CONNECTING",
	"WPA_STATE_CONNECTED",
};

/* this enum captures the state of the daemon */
typedef enum {
	WIFISTAD_STATE_UNINITIALIZED,
	WIFISTAD_STATE_SCANNING,
	WIFISTAD_STATE_WPA_CONNECTING,
	WIFISTAD_STATE_WPA_CONNECTED,
	WIFISTAD_STATE_MAX
} wifistad_state_t;


const char *WIFISTAD_STATE_STR[] = {
	"UNINITIALIZED",
	"SCANNING",
	"WPA_CONNECTING",
	"WPA_CONNECTED",
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
	WIFISTAD_EVENT_DO_NETCHECK,
	WIFISTAD_EVENT_NETCHECK_SUCCEEDED,
	WIFISTAD_EVENT_NETCHECK_FAILED,

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
	"DO_NETCHECK",
	"NETCHECK_SUCCEEDED",
	"NETCHECK_FAILED"
};


static uint8_t reconn_count = 1;
static char *scan_results = NULL;
static struct event_base *s_evbase;
static wpa_state_t s_wpa_state = WPA_STATE_NOT_READY;

static void prv_save_scan_results(char *results);
static void prv_scan_started_callback(void *my_param, void *result);
void  wifistad_close ();
void wifistad_attr_on_close(int status, void *context);
static void prv_handle_connecting_tmout (wpa_manager_t *m);
void prv_wpa_event_callback(evutil_socket_t fd, short evts, void *param);
static int queue_event(wifistad_event_t event);
static void on_netcheck_complete(int status, void *context);

extern int prv_send_req_ping_networks(void);
extern void wpa_manager_dump();

// [HUB-740]
// let's scan twice before sending the result back
static uint8_t  s_scan_count = 0;

static uint8_t  s_has_wifi_cfg_info = 0;

/* we maintain three timers:
 *    0 - periodic check timer to check and restart the supplicant connection
 *    1 - network check delay timer to back off the network check
 *    2 - setup timer to notify user of failed setup
 */
typedef enum {
	WPA_PERIODIC_TIMER=0,
	NETCHECK_DELAY_TIMER,
	SETUP_TIMER,
	NUM_TIMERS
} timer_id_t;

// Forward declare the callbacks
static void push_event_for_timer(evutil_socket_t fd, short what, void *arg);
static void wpa_periodic_check(evutil_socket_t fd, short what, void *arg);
static void on_setup_timer(evutil_socket_t fd, short what, void *arg);

static const event_callback_fn s_timer_callbacks[NUM_TIMERS] = {
	wpa_periodic_check,
	push_event_for_timer,
	on_setup_timer
};

static void *s_timer_contexts[NUM_TIMERS] = {
	NULL,
	(void *)WIFISTAD_EVENT_DO_NETCHECK,
	NULL,
};

static struct event *s_timer_evs[NUM_TIMERS];

static void destroy_timer_events(void)
{
	for (int i=0; i < NUM_TIMERS; i++) {
		if (s_timer_evs[i]) {
			event_del(s_timer_evs[i]);
			event_free(s_timer_evs[i]);
			s_timer_evs[i] = NULL;
		}
	}
}

static int prv_create_timer_events(void)
{
	for (int i=0; i < NUM_TIMERS; i++) {
		// Create the periodic timer event
		s_timer_evs[i] = evtimer_new(s_evbase, s_timer_callbacks[i], s_timer_contexts[i]);
		if (s_timer_evs[i] == NULL) {
			AFLOG_ERR("prv_create_timer_events:errno=%d", errno);
			destroy_timer_events();
			return -1;
		}
	}
	return 0;
}

static void set_timer(timer_id_t timerId, int timeoutSec)
{
	struct timeval tv = { timeoutSec, 0 };
	event_del(s_timer_evs[timerId]);
	event_add(s_timer_evs[timerId], &tv);
}

static void cancel_timer(timer_id_t timerId)
{
	event_del(s_timer_evs[timerId]);
}

static void push_event_for_timer(evutil_socket_t fd, short what, void *arg)
{
	queue_event((wifistad_event_t)arg);
}

// we want to cap the wifi setup at ~1 minute or 60 seconds
#define SETUP_TIMER_CAP		60
// this is the amount of time we allow for one Wi-Fi setup operation
#define SETUP_TIMER_INC		20

// This function resets the setup timer out by SETUP_TIMER_INC (20 sec)
// basically kicking the timeout of the Wi-Fi setup can down the road.
// However, it imposes a cap of 60 seconds total for the Wi-Fi setup.
// When the setup timer expires, and the Wi-Fi connection is still not
// complete, we both report the setup state to the app and revert to the
// previous good setup, if one is available.
static time_t s_start_conn_time = 0;

static void set_setup_timer(void)
{
	if (s_start_conn_time == 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		s_start_conn_time = now.tv_sec;
		AFLOG_DEBUG1("set_setup_timer:timeout=%d:initiate timer for wifi setup", SETUP_TIMER_INC);
		set_timer(SETUP_TIMER, SETUP_TIMER_INC);
	}
	else {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		AFLOG_DEBUG2("set_setup_timer:end=%ld,start=%ld", now.tv_sec, s_start_conn_time);

		if (now.tv_sec - s_start_conn_time < SETUP_TIMER_CAP - 5) {
			AFLOG_DEBUG1("set_setup_timer:timeout=%d:initiate timer for wifi setup", SETUP_TIMER_INC);
			set_timer(SETUP_TIMER, SETUP_TIMER_INC);
		}
	}
}

static void on_setup_timer(evutil_socket_t fd, short what, void *arg)
{
	// We've given up on this Wi-Fi setup attempt
	// Reset the start time for the next Wi-Fi setup attempt
	s_start_conn_time = 0;
	queue_event(WIFISTAD_EVENT_WPA_CONNECTING_TMOUT);
}

// network ID cache before echo check succeeds
static int s_netcheck_network_id = -1;
static int s_netcheck_delay;



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
	} else {
		// WIFI setup: AP is connected, but echo to service failed
		// Update wifi setup state to the service
		m->wifi_setup.setup_state = WIFI_STATE_ECHOFAILED;
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
	AFLOG_DEBUG2("prv_post_echo_check_processing::free wifi data, RESET_WIFI_SETUP(m)");
	if (m->wifi_setup.data_p != NULL) {
		free(m->wifi_setup.data_p);
	}
	RESET_WIFI_SETUP(m,1);

	return;
}


// attempt to connect to wifi with the configured userid/auth
static int prv_attempt_conn_with_config()
{
	int				rc = -1;
	wifi_cred_t		*wifi_cred = malloc(sizeof(wifi_cred_t));

	if (wifi_cred == NULL) {
		AFLOG_ERR("prv_attemp_conn_with_config:: malloc failed, errno=%d, %s",
				  errno, strerror(errno));
		return (-1);
	}
	memset(wifi_cred, 0, sizeof(wifi_cred_t));
	if (wifista_get_wifi_cred(wifi_cred) == 0) {
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

	// user just initiated wifi setup. don't interfere with it
	if (m->wifi_setup.who_init_setup == USER_REQUEST) {
		goto exit;
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
		// Check to see if the worker thread has hung
		if (m->current_op.pending > 5) { // pending should never be greater than 1
			// terminate the worker thread
			AFLOG_INFO("prv_wpa_periodic_check:: work thread hangs -> post terminated");
			wpa_manager_dump(); // debug info
			wifista_wpa_post_event(WPA_EVENT_ID_TERMINATED, NULL);
		}
		// Check if we've been waiting a long time to set up the network
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

exit:
	// set up next event
	set_timer(WPA_PERIODIC_TIMER, PERIODIC_TIMER_PERIOD_SEC);
	return;
}

static void prv_state_machine(evutil_socket_t fd, short events, void *param)
{
	static wifistad_state_t state = WIFISTAD_STATE_UNINITIALIZED;
	wifistad_event_t event = (wifistad_event_t)param;

	AFLOG_DEBUG2("prv_state_machine:: events=%d,param=%p", events, param);
	if (event < 0 || event > WIFISTAD_EVENT_MAX) {
		AFLOG_ERR("prv_state_machine:: invalid input");
		return;
	}

	wpa_manager_t *m = wifista_get_wpa_mgr();

	wifistad_state_t old_state = state;

	switch (state) {
		case WIFISTAD_STATE_UNINITIALIZED:
			switch (event) {
				case WIFISTAD_EVENT_READY: {
					// We entering SCANNING state, but disable AUTO. So, scanning only
					// commences when the user request for it.
					state = WIFISTAD_STATE_SCANNING;
					AFLOG_DEBUG2("prv_state_machine: reset_wifi_setup");
					RESET_WIFI_SETUP(m,0);

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
				AFLOG_INFO("prv_state_machine:who_init_setup=%s:scanning process initiated",
						   (m->wifi_setup.who_init_setup == USER_REQUEST) ? "USER":"SYS");
				wpa_manager_scan_async(prv_scan_started_callback, NULL);
			}
			else if (event == WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE) {
				AFLOG_DEBUG3("prv_state_machine:: attempt to connect, scan_results =(%s)",
							 (scan_results == NULL) ? "NULL" : scan_results);
				wifista_wpa_process_scan_results(scan_results);
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

				case WIFISTAD_EVENT_SCAN: {  // conn possible failed, go back to scanning state
					state = WIFISTAD_STATE_SCANNING;
				}
				break;

				case WIFISTAD_EVENT_WPA_CONNECTING_TMOUT:
					state = WIFISTAD_STATE_SCANNING;
					prv_handle_connecting_tmout(m);
					break;

				case WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE:
					if (m->wifi_setup.setup_event == WPA_EVENT_ID_WIFI_SCAN_REQUESTED) {
						wifista_wpa_process_scan_results(scan_results);
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
					// go to scanning state
					state = WIFISTAD_STATE_SCANNING;
					cancel_timer(NETCHECK_DELAY_TIMER);
					break;

				case WIFISTAD_EVENT_SCAN:
					AFLOG_INFO("prv_state_machine:who_init_setup=%s:scanning process initiated",
							  (m->wifi_setup.who_init_setup == USER_REQUEST) ? "USER":"SYS");
					wpa_manager_scan_async(prv_scan_started_callback, NULL);
					break;

				case WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE:
					wifista_wpa_process_scan_results(scan_results);
					break;

				case WIFISTAD_EVENT_WPA_CONNECTING_TMOUT:
					// update the WPA status information
					wpa_manager_status_async(NULL, NULL);

					AFLOG_DEBUG2("prv_state_machine_timeout:setup_state=%d,who_init=%d",
								 m->wifi_setup.setup_state, m->wifi_setup.who_init_setup);
					break;

				case WIFISTAD_EVENT_DO_NETCHECK :
					if (check_network(s_evbase, echo_service_host_p, m->ctrl_iface_name, NETCHECK_USE_ECHO,
									  on_netcheck_complete, (void *)s_netcheck_network_id, ECHO_CHECK_TIMEOUT_MS) < 0) {
						AFLOG_ERR("prv_wpa_event_callback_echo_fail:errno=%d", errno);
					}
					break;

				case WIFISTAD_EVENT_NETCHECK_FAILED :
					m->wifi_setup.setup_state = WIFI_STATE_ECHOFAILED;
					if (s_netcheck_delay <= NETCHECK_DELAY_INITIAL_SEC) {
						set_setup_timer(); // kick the can down the road a little more
					} else {
						prv_post_echo_check_processing(0);
					}
					s_netcheck_delay *= NETCHECK_DELAY_MULTIPLIER; // exponential backoff with a cap at 20 sec
					if (s_netcheck_delay > NETCHECK_DELAY_CAP) {
						s_netcheck_delay = NETCHECK_DELAY_CAP;
					}

					set_timer(NETCHECK_DELAY_TIMER, s_netcheck_delay);
					break;

				case WIFISTAD_EVENT_NETCHECK_SUCCEEDED :
					m->wifi_setup.network_id = s_netcheck_network_id;
					// clear the connection start time to indicate we're not in setup anymore
					s_start_conn_time = 0;
					cancel_timer(SETUP_TIMER);
					prv_post_echo_check_processing(1);
					break;

				default:
					break;
			}
			break;

		default:
			AFLOG_WARNING("prv_state_machine::unsupported state=%d", state);
			break;
	}

	// independent of the state -- we lost our connection to the WPA supplicant
	if ((event == WIFISTAD_EVENT_WPA_TERMINATED) && (state != WIFISTAD_STATE_UNINITIALIZED)) {
		state = WIFISTAD_STATE_UNINITIALIZED;
		AFLOG_INFO("wpa_supplicant_lost::Connection to wpa_supplicant lost - trying to reconnect");

		if (s_wpa_state == WPA_STATE_NOT_READY) { // wpa is not doing anything
			wpa_manager_destroy();
			cancel_timer(SETUP_TIMER);
			cancel_timer(NETCHECK_DELAY_TIMER);
			wifista_bootup   = 1;    // restart wpa

			if (wpa_manager_init(s_evbase, NULL, NULL) < 0) {
				AFLOG_ERR("wifistad::wpa_manager_init: failed.  Exit");
				wifistad_close ();
				exit(EXIT_FAILURE);
			}
		}
	}

	AFLOG_INFO("prv_state_machine:old_state=%s(%d),new_state=%s(%d),event=%s(%d)",
			   WIFISTAD_STATE_STR[old_state], old_state,
			   WIFISTAD_STATE_STR[state], state,
			   WIFISTAD_EVENT_STR[event], event);
}


/* queue_event
 *
 * Queue up the specified event after the specified timeout
 */
static int queue_event(wifistad_event_t event)
{
	AFLOG_INFO("queue_event:event=%s(%d):event queued", WIFISTAD_EVENT_STR[event], event);
	struct timeval tv = { 0, 0 };

	// your call will be answered in the order received
	return event_base_once(s_evbase, -1, EV_TIMEOUT, prv_state_machine, (void *)event,
						   event_base_init_common_timeout(s_evbase, &tv));
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
	wifista_set_wifi_steady_state(m->wifi_setup.setup_state);

	if (m->wifi_setup.data_p != NULL) {
		free(m->wifi_setup.data_p);
	}
	RESET_WIFI_SETUP(m,1);

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
		if ((tok[4] != NULL) && (strncmp(tok[4], "\\x00", 4) != 0)) {
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
		AFLOG_DEBUG3("SCAN FAILED");
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

	s_scan_count = 0;
	return;
}

static void on_netcheck_complete(int status, void *context)
{
	if (status != 0) {
		AFLOG_INFO("on_netcheck_complete_failed:status=%d", status);
		queue_event(WIFISTAD_EVENT_NETCHECK_FAILED);
	} else {
		AFLOG_INFO("on_netcheck_complete_succeeded");
		queue_event(WIFISTAD_EVENT_NETCHECK_SUCCEEDED);
	}
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

	AFLOG_DEBUG1("prv_wpa_event_callback:initial_state=%s(%d),eventId=%s(%d)",
		   WPA_STATE_STR[s_wpa_state], s_wpa_state, WPA_EVENT_ID_STR[event->id], event->id);

	switch(event->id) {
		case WPA_EVENT_ID_CONNECTED: {
			wifi_cred_t   *wCred_p  = (wifi_cred_t *)m->wifi_setup.data_p;
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

			// the WPA is connected to the AP
			s_wpa_state = WPA_STATE_CONNECTED;

			// update the states
			queue_event(WIFISTAD_EVENT_WPA_CONNECTED);

			// we need to save the connect info
			if ((wCred_p) && (wCred_p->prev_provisioned == 0)) {
				wifista_store_wifi_cred(wCred_p);

				AFLOG_DEBUG1("prv_wpa_event_callback:s_has_wifi_cfg_info=1");
				s_has_wifi_cfg_info = 1;
			}
			// script file to execute when wifi associated
			if (file_exists(WIFI_EVENT_SH_FILE)) {
				AFLOG_INFO("wifistad_exec_connected:script=%s", WIFI_EVENT_SH_FILE);

				af_util_system("%s %s", WIFI_EVENT_SH_FILE, "connected");
			}

			// kick off a short delay before starting network check
			// save the network id for storing when network check succeeds
			s_netcheck_network_id = netid;
			s_netcheck_delay = 2;
			set_timer(NETCHECK_DELAY_TIMER, s_netcheck_delay);

			break;
		}

		case WPA_EVENT_ID_DISCONNECTED:
			if (s_wpa_state != WPA_STATE_NOT_READY) {
				s_wpa_state = WPA_STATE_READY;
				wpa_manager_status_async(NULL, NULL);
				wifista_set_wifi_steady_state(WIFI_STATE_NOTCONNECTED);
				queue_event(WIFISTAD_EVENT_WPA_DISCONNECTED);

				if (file_exists(WIFI_EVENT_SH_FILE)) {
					AFLOG_INFO("wifistad_exec_disconnected:script=%s", WIFI_EVENT_SH_FILE);
					af_util_system("%s %s", WIFI_EVENT_SH_FILE, "disconnected");
				}
			}
			break;


		case WPA_EVENT_ID_SCAN_RESULTS: {
			// scan in the background, but we just ignore the result if no one is asking for
			// it or while we are in the middle of connecting
			if ((m->wifi_setup.who_init_setup != INIT_NONE) &&
				(m->wifi_setup.setup_event != WPA_EVENT_ID_WIFI_CREDENTIALS)) {
				if (s_scan_count < 2) {
					AFLOG_INFO("wifistad:: Perform a second scan before sending result");
					wifista_wpa_post_event(WPA_EVENT_ID_WIFI_SCAN_REQUESTED, (void *)&(m->wifi_setup));
					break;
				}
				AFLOG_DEBUG3("prv_wpa_event_callback:: save scan result");

				// we got the scan results back - two options:
				//	1) auto_connect
				//	2) user wifi setup
				prv_save_scan_results((char *)event->result);
				queue_event(WIFISTAD_EVENT_SCAN_RESULTS_AVAILABLE);
			}
		}
		break;


		case WPA_EVENT_ID_READY: {
			uint8_t  len;

			if (s_wpa_state == WPA_STATE_NOT_READY) {
				s_wpa_state = WPA_STATE_READY;

				// give the wpa supplicant time to get ready
				wpa_manager_status_async(NULL, NULL);
				queue_event(WIFISTAD_EVENT_READY);
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

				s_scan_count++;
				AFLOG_DEBUG2("prv_wpa_event_callback:: SCAN request, start scan");
				WIFI_SETUP_SCAN_REQUEST(m);
				queue_event(WIFISTAD_EVENT_SCAN);
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
					m->wifi_setup.setup_state = WIFI_STATE_ASSOCATIONFAILED;
					wait_for_tmout = 1;
				}
				else if (cResult == WPA_CONN_RESULT_HANDSHAKE_FAILED) {
					m->wifi_setup.setup_state = WIFI_STATE_HANDSHAKEFAILED;
					wait_for_tmout = 1;
				}
				else if (cResult == WPA_CONN_RESULT_INVALID_SSID) {
					m->wifi_setup.setup_state = WIFI_STATE_SSID_NOT_FOUND;
				}
				else if (cResult == WPA_CONN_RESULT_SET_PSK_FAILED) {
					m->wifi_setup.setup_state = WIFI_STATE_HANDSHAKEFAILED;
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
					m->wifi_setup.setup_state = WIFI_STATE_UNKNOWN;
				}

				/* If all the user specified wifi config inputs are valid, then we need to wait until
				 * all attempts to associate completed before we can delete the network
				 */
				if (!wait_for_tmout) {
					// delete the "unsuccessful network from add_network command" if it is not deleted
					wpa_manager_remove_network_async(NULL, NULL, m->wifi_setup.network_id);

					// remember the network id or err code.  Notify service/APP and clean up
					wifista_setup_send_rsp(&m->wifi_setup);
					wifista_set_wifi_steady_state(m->wifi_setup.setup_state);

					if (m->wifi_setup.data_p != NULL) {
						free(m->wifi_setup.data_p);
						m->wifi_setup.data_p = NULL;
					}
					AFLOG_INFO("prv_wpa_event_callback:: Done - RESET_WIFI_SETUP");
					RESET_WIFI_SETUP(m,1);

					/* failed, revert to previous network */
					if (m->assoc_info.id > 0) {
						AFLOG_INFO("prv_wpa_event_callback:: reconnect to network (id=%d, ssid=%s)",
								   m->assoc_info.id, m->assoc_info.ssid);
						wpa_manager_connect_async(NULL, NULL, m->assoc_info.id);
					}
					// let's go back to scanning state
					queue_event(WIFISTAD_EVENT_SCAN);
				}
				else {
					if (cResult == WPA_CONN_RESULT_TEMP_DISABLED) {
						AFLOG_INFO("prv_wpa_event_callback::TEMP_DISABLED, start TMOUT timer");
						// Kick the can down the road
						set_setup_timer();
					}
				}
			}
			else {  // connecting seems to be OK
				queue_event(WIFISTAD_EVENT_WPA_CONNECTING);

				if (cResult > 0) {
					AFLOG_INFO("prv_wpa_event_callback_connecting:id=%d", cResult);
					m->wifi_setup.network_id = cResult;  // store the add_network id
					set_setup_timer();

					if (m->wifi_setup.setup_state != WIFI_STATE_PENDING) {
						m->wifi_setup.setup_state = WIFI_STATE_PENDING;
						wifista_setup_send_rsp(&m->wifi_setup);
						wifista_set_wifi_steady_state(WIFI_STATE_PENDING);
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
				RESET_WIFI_SETUP(m,1);
				memset(&m->assoc_info, 0, sizeof(wpa_sta_assoc_t));

				queue_event(WIFISTAD_EVENT_WPA_TERMINATED);
			}
			break;


		case WPA_EVENT_ID_CFG_CHECK: {
				if ((s_wpa_state == WPA_STATE_READY) || (s_wpa_state == WPA_STATE_CONNECTING)) {
					AFLOG_DEBUG1("prv_wpa_periodic_check:s_start_conn_time=%ld,s_has_wifi_cfg_info=%d",
								 s_start_conn_time, s_has_wifi_cfg_info);
					if (!s_start_conn_time && s_has_wifi_cfg_info) {
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

	AFLOG_DEBUG1("prv_wpa_event_callback:final_state=%s(%d)", WPA_STATE_STR[s_wpa_state], s_wpa_state);


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
					   wifistad_attr_on_notify,			// notify callback
					   wifistad_attr_on_owner_set,		// owner set callback
					   wifistad_attr_on_get_request,	// owner get callback
					   wifistad_attr_on_close,			// close callback
					   wifistad_attr_on_open,			// open callback
					   NULL);							// context
	if (err != AF_ATTR_STATUS_OK) {
		AFLOG_ERR("wifistad::Unable to init the server, err=%d", err);
		return (-1);
	}
	return (0);
}

extern const char REVISION[];
extern const char BUILD_DATE[];

/****************
 *
 * wifistad main
 *
 ***************/
int main()
{
	int32_t  result;

	openlog("wifistad", LOG_PID, LOG_USER);

	AFLOG_INFO("start_wifistad:revision=%s,build_date=%s", REVISION, BUILD_DATE);

	if (NETIF_NAMES_GET() < 0) {
		AFLOG_WARNING("wifistad:: failed to get network interface names; using defaults");
	}

	/* load up the Wi-Fi credentials cache and block if PSK should be available but isn't */
	uint8_t loadStatus;
	while(1) {
		loadStatus = wifista_load_wifi_cred();
		if (loadStatus != 2) {
			break;
		}
		sleep(5);
	}

	// We have valid configuration information only if the load function returns 0
	s_has_wifi_cfg_info = (loadStatus == 0);
	AFLOG_DEBUG1("wifistad:: s_has_wifi_cfg_info=%d", s_has_wifi_cfg_info);

	// initialize the MAC whitelist data structures.
	wifistad_init_mac_wl();

	hub_config_service_env_init();

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

	if (wpa_manager_init(s_evbase, NULL, NULL) < 0) {
		AFLOG_ERR("wifistad::wpa_manager_init: failed");
		goto wifistad_exit;
	}

	if (prv_create_timer_events() != 0) {
		AFLOG_ERR("wifistad_create_timers:errno=%d", errno);
		goto wifistad_exit;
	}

	/* start up the periodic timer */
	set_timer(WPA_PERIODIC_TIMER, PERIODIC_TIMER_PERIOD_SEC);

	// This should be the last
	if (wifistad_conn_to_attrd(s_evbase) < 0) {
		goto wifistad_exit;
	}

	// Start the event loop
	AFLOG_INFO("wifistad:: running");
	if (event_base_dispatch(s_evbase)) {
		AFLOG_ERR("wifistad::Error running event loop");
	}


wifistad_exit:       /* clean up */
	wifistad_close();
	return 0;
}


/* wrapper function to close things up for wifistad */
void wifistad_close()
{
	AFLOG_INFO("wifistad::Service is shutting down");
	wpa_manager_destroy();

	af_attr_close();

	destroy_timer_events();

	if (s_evbase) {
		event_base_free(s_evbase);
		s_evbase = NULL;
	}

	// this can still have memory allocate. if so, free it.
	if (scan_results != NULL) {
		free(scan_results);
		scan_results = NULL;
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
		exit(EXIT_FAILURE);
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

