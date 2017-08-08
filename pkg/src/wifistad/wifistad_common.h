/*
 * file wifistad_common.h
 *
 * File contains definitions used in more than one files.
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */
#ifndef __WIFISTAD_COMMON_H_
#define __WIFISTAD_COMMON_H_

// wifi event hook script
#define WIFI_EVENT_SH_FILE      "/usr/bin/wifi_event.sh"

// utilties
int8_t file_exists(const char *filename);

#endif // __WIFISTAD_COMMON_H_
