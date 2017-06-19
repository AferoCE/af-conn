/*
 * hub_netconn_states.h  
 *
 * This file contains definitions for network connection states 
 * and its related functionality. 
 *
 * Copyright (c) 2016, Afero, Inc. All rights reserved.
 *
 * Bento Team 
 */

#ifndef _HUB_NETCONN_STATES_H_
#define _HUB_NETCONN_STATES_H_


/* 
 * network connection status type
 * 
 * Legends:
 *   I=Interface   D=DOWN                          
 *                 U=UP 
 *                 N=NOT_SUPPORTED 
 *
 *   S=Service     U=UNKNOWN
 *                 F=FAIL
 *                 S=SUCCESS
 *                 X=DON'T CARE
 *
 * Examples:
 * ID_SU = (Interface Down, Service Unknown) -- at init 
 * IU_SU = (Interface UP, Service Unkonw)    -- at init, during transition  
 * IU_SS = (Interface UP, Service Sucess)    -- normal operation 
 * IU_SF = (Interface UP, Service FAIL)      -- during operation, service failed 
 * ID_SX = (Interface DOWN, Doesn't matter)  -- during operation,  interface deleted        
 * IN_SX = (interface NOT_SUPPORTED, Don't care) 
 *
 * Note: If an interface is not supported, then the system is doesn't have to 
 *       monitor it.  
 */
typedef enum {
    /* INIT */
    NETCONN_STATUS_ITFDOWN_SU = 0,

    /* INIT tansition state: Dev name is created, no service yet (i.e no ip) */ 
    NETCONN_STATUS_ITFDOWN_SX = 1,

    /* network connection (ie. ethernet) not supported */
    NETCONN_STATUS_ITFNOTSUPP_SX = 2,

    /* Interface is UP, Service UNKNOWN */
    NETCONN_STATUS_ITFUP_SU  = 3,

    /* Interface is UP, Service failed */
    NETCONN_STATUS_ITFUP_SF  = 4,

    /* Interface is UP, confirm connection is good (i.e ping to conclave ok) */
    NETCONN_STATUS_ITFUP_SS  = 5,

    NETCONN_STATUS_MAX
} hub_netconn_status_t;


#endif // _HUB_NETCONN_STATES_H_
