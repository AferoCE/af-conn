/*
 * hub_netconn_status.c
 *
 * This contains the definition and implementation of utilities about 
 * the hub(bento) configuration (used by the connmgr)
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */

#include "../include/hub_netconn_state.h"

const char *NETCONN_STATUS_STR[] = {
    "Interface down, Service Unknown",
    "Interface down, Service Don't care",
    "Interface Not supported, Service Don't care",
    "Interface UP, Service Unknown",
    "Interface UP, Service Failed",
    "Interface UP, Service Success",
};
