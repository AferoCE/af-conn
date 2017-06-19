/*
* connmgr_attributes.h
*
* This contains the API defintions for attribute implementation.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/
#ifndef _CONNMGR_ATTRIBUTES_H_
#define _CONNMGR_ATTRIBUTES_H_

#include "af_attr_client.h"


/* The network type definition
 * (This needs to match the device attribute registry specified value).
 *
 * ref: http://wiki.afero.io/display/FIR/Device+Attribute+Registry
 */
#define HUB_NETWORK_TYPE_NONE      (-1)
#define	HUB_NETWORK_TYPE_ETHERNET  (0)
#define	HUB_NETWORK_TYPE_WLAN      (1)
#define	HUB_NETWORK_TYPE_WAN       (2)


// APIs
extern void cm_attr_set_network_type ();


// attrd related callbacks
extern void connmgr_attr_on_notify(uint32_t attributeId, uint8_t *value, int length, void *context);
extern int connmgr_attr_on_owner_set(uint32_t attributeId, uint8_t *value, int length, void *context);
extern void connmgr_attr_on_set_finished(int status, uint32_t attributeId, void *context);
extern void connmgr_attr_on_get_request(uint32_t attributeId, uint16_t getId, void *context);
extern void connmgr_attr_on_open(int status, void *context);
extern void connmgr_attr_on_close(int status, void *context);

#endif  // _CONNMGR_ATTRIBUTES_H_
