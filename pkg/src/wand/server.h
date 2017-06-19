/*
 * server.h -- IPC server include file
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Clif Liu and Tina Cheung
 */

#include <stdint.h>
#include <pthread.h>
#include <af_ipc_server.h>


extern uint8_t  periodic_rpt_rssi;
#define GET_PERIODIC_RPT_RSSI() (periodic_rpt_rssi)


/* provided by WAN daemon: get connection status
   returns NULL if failure
 */
char *wan_get_status(void);

/* provided by WAN daemon: set debug level
   returns 0 if successful; -1 otherwise
*/
int wan_set_debug_level(int level);

/* provided by WAN daemon: return nonzero if WAN is working */
int wan_exists(void);

/* provided by server: notify attrd whether the WAN exists or not */
void notify_wan_existence(void);

/* provided by server: start server
   returns 0 if successful; -1 otherwise
*/
int wan_ipc_init(struct event_base *base);

/* provided by server: shuts down server */
void wan_ipc_shutdown(void);


/* wand report rssi value */
extern void wan_rpt_rssi_info();
