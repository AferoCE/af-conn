/*
* connmgr_select_engine.h
* (Select Engine == SE)
*
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#ifndef _CONNMGR_SELECT_ENGINE_H_
#define _CONNMGR_SELECT_ENGINE_H_
/*
 * given a new network interface connection cb, compare with the current
 * active (i.e inuse network), if the given network connection has a
 * higher priority, then make the new network interface the active one
 */
extern cm_conn_monitor_cb_t *
cm_select_pri_netitf(cm_conn_monitor_cb_t   *conn_a,
                     cm_conn_monitor_cb_t   *conn_b);


/* event triggers call to the RE (rule engine)
 * RE -> takes some input, based on the criteria
 *  ==> spits out the result
 */
//extern cm_conn_monitor_cb_t *
// cm_select_next_inuse_network (cm_dev_status_t         trigger_ev,
//                             cm_conn_monitor_cb_t    *trigger_ev_conn_p);

#endif //_CONNMGR_SELECT_ENGINE_H_