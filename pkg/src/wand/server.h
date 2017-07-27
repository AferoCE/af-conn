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


#define WAN_ITF_STATE_NOT_AVAILABLE 0
#define WAN_ITF_STATE_DISABLED      1
#define WAN_ITF_STATE_PENDING       2
#define WAN_ITF_STATE_UP            3

/* provided by wand for server to gather WAN information */

char *wan_apn(void);
uint8_t wan_interface_state(void);
void wand_shutdown(void);
struct event_base *wand_get_evbase();

/* provided by server for wand to use */

/* start server; returns 0 if successful; -1 otherwise */
int wan_ipc_init(struct event_base *base);

/* shuts down server */
void wan_ipc_shutdown(void);
