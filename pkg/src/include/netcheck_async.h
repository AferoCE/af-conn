/*
* netcheck_async.h
*
* Asynchronously check to see if we're connected to the internet
*
* Copyright (c) 2016-2018, Afero Inc. All rights reserved.
*/
#ifndef __NETCHECK_ASYNC_H__
#define __NETCHECK_ASYNC_H__

#include <event2/event.h>

typedef enum {
    NETCHECK_USE_ECHO = 0,
    NETCHECK_USE_PING,
} netcheck_type_t;

#define NETCHECK_ERROR_TIMED_OUT -2

/* error is:
 *   0                           if network check succeeded
 *   errno                       if a failure occurred
 *   AF_NETCHECK_ERROR_TIMED_OUT if operation timed out
 */
typedef void (*netcheck_callback_t)(int error, void *context);

/*
 * API to confirm whether the network connection is good.
 *
 * send an echo packet to 'echo.dev.afero.io'
 * or
 * ping a well known destination.
 *
 */
int check_network(struct event_base *base,
                  const char *host,              // service name (echo) or IP addr (ping)
                  const char *itf_string,        // interface name
                  netcheck_type_t check_type,    // use ping or echo?
                  netcheck_callback_t callback,  // callback to call with result
                  void *context,                 // context for callback
                  int timeout_msec);             // timeout in milliseconds

#endif // __NETCHECK_ASYNC_H__
