/*
* hub_config.h
*
* This contains the definition and implementation of utilities about
* the hub(bento) configuration (required by daemon managing connectivity).
*
* Copyright (c) 2019-present, Afero Inc. All rights reserved.
*/

#ifndef _HUB_CONFIG_H_
#define _HUB_CONFIG_H_

extern uint32_t           cm_wifi_opmode;

extern uint32_t
hub_wireless_opmode(const char *ifname);

#endif //_HUB_CONFIG_H_
