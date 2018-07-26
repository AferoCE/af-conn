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


/* provided by wand for server to gather WAN information */

char *wan_apn(void);
void wand_shutdown(void);
struct event_base *wand_get_evbase();

/* provided by server for wand to use */

/* start server; returns 0 if successful; -1 otherwise */
int wan_ipc_init(struct event_base *base);

/* shuts down server */
void wan_ipc_shutdown(void);
