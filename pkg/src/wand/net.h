/*
 * net.h -- network watcher definitions
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Clif Liu and Tina Cheung
 */

#ifndef __NET_H__
#define __NET_H__

#define NETWATCH_EVENT_NETWORK_DOWN 0

typedef void (*netwatch_callback_t)(int event, void *context);

int netwatch_init(char *dev, netwatch_callback_t callback, void *context);
void netwatch_shutdown(void);

#endif // __NET_H__
