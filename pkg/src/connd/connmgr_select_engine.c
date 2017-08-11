/*
* connmgr_select_engine.c
* (Select Engine == SE)
*
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>
#include <syslog.h>
#include <event.h>

#include "connmgr.h"
#include "connmgr_stats.h"
#include "connmgr_select_engine.h"
#include "connmgr_util.h"
#include "af_log.h"
#include "../include/hub_netconn_state.h"
#include "connmgr_attributes.h"
#include "af_util.h"

extern void cm_set_itf_up(cm_conn_monitor_cb_t   *net_conn_p,
                          hub_netconn_status_t   new_status);
extern char *NETCONN_STATUS_STR[];


/*
 * given two network interface connection cbs, compare the two.
 *
 * Select the interface that is active, and has the higher priority.
 * Otherwise, NULL
 */
cm_conn_monitor_cb_t *
cm_select_pri_netitf(cm_conn_monitor_cb_t   *conn_a,
                     cm_conn_monitor_cb_t   *conn_b)
{

    if ((conn_a == NULL) && (conn_b != NULL)) {
        if (conn_b->conn_active) {
            return conn_b;
        }
    }

    if ((conn_a != NULL) && (conn_b == NULL)) {
        if (conn_a->conn_active) {
            return conn_a;
        }
    }

    if ((conn_a != NULL) && (conn_b != NULL)) {
        switch (conn_a->conn_active) {
            case 1:
                if (conn_b->conn_active) {
                    if (conn_a->mon_policy.priority < conn_b->mon_policy.priority) {
                        return conn_a;
                    }
                    else {
                        return conn_b;
                    }
                }
                break;

            case 0:
                if (conn_b->conn_active) {
                    return conn_b;
                }
                break;

            default:
                AFLOG_ERR("cm_select_pri_netitf:: Unsupport conn_a (%s), active value=%d",
                        conn_a->dev_name, conn_a->conn_active);
                break;
        }

    }

    return NULL;
}



/* Connection event triggers call to this routine
 *
 * trigger_ev:
 *  NETCONN_STATUS_ITFUP_SU, NETCONN_STATUS_ITFUP_SS
 *  NETCONN_STATUS_ITFDOWN_SU,
 *  NETCONN_STATUS_ITFDOWN_SX,
 *  NETCONN_STATUS_ITFUP_SF
 *
 * trigger_ev_conn_p
 *  network connection cb that triggers this event
 *
 *  Return:
 *     conn_monito_cb that we are going to pass traffic.  This
 *     could be the current network, or another active with the
 *     preferred priority.
 */
static cm_conn_monitor_cb_t *
cm_select_next_inuse_network (hub_netconn_status_t    trigger_ev,
                              cm_conn_monitor_cb_t    *trigger_ev_conn_p)
{
    cm_conn_monitor_cb_t    *inuse_p = CM_GET_INUSE_NETCONN_CB();
    cm_conn_monitor_cb_t    *selected_p = NULL;

    if ((trigger_ev_conn_p == NULL) ||
        (trigger_ev < 0) || (trigger_ev >= NETCONN_STATUS_MAX )) {
        AFLOG_ERR("cm_select_next_inuse_network:: Invaid input, trigger_ev=%d, ptr=%p",
                   trigger_ev, trigger_ev_conn_p);
        return NULL;
    }
    AFLOG_INFO("cm_select_next_inuse_network:: Network (%s) with trigger_ev=%d (%s), ptr=%p",
               trigger_ev_conn_p->dev_name,
               trigger_ev,
               NETCONN_STATUS_STR[trigger_ev],
               trigger_ev_conn_p);

    switch (trigger_ev) {
        case NETCONN_STATUS_ITFUP_SU:  /* itf UP, but not confirm connection with service */
        case NETCONN_STATUS_ITFUP_SS:  /* itf UP, confirm connection with service */
            /* This interface is up - should we switch to it */
            if (inuse_p == trigger_ev_conn_p) {
                // This could be a case when the INUSE network flop, and flip immediately
                // continue to use current INUSE network - but may want to refresh the routes
                selected_p = inuse_p;
            }
            else {
                selected_p = cm_select_pri_netitf(inuse_p, trigger_ev_conn_p);
                if (selected_p == NULL) {
                    /* Something went wrong - and no network is selected.
                       Let's stick with the current known INUSE network */
                    selected_p = inuse_p;
                }
                else {
                    if ((inuse_p) && (inuse_p->dev_link_status == NETCONN_STATUS_ITFUP_SS) &&
                        (selected_p->dev_link_status < NETCONN_STATUS_ITFUP_SS))
                    {
                        // use case see: [HUB-430] - wifi outage causes connectivity flapping
                        // the current 'inuse' network definitely has connective to service,
                        // but the new selected network doesn't.  Continue to use the current network
                        selected_p = inuse_p;
                    } else {
                        // othewise, we use the selected network
                        AFLOG_INFO("cm_select_next_inuse_network:: Selected INUSE network - %s",
                                   selected_p->dev_name );
                    }
                }
            }
            break;


        case NETCONN_STATUS_ITFDOWN_SU: /* itf DOWN, connection service unknown */
        case NETCONN_STATUS_ITFDOWN_SX: /* itf DOWN, connection service don't care */
        case NETCONN_STATUS_ITFUP_SF:   /* itf UP, service connection FAILED */
            /* This interface just went down, need to switch to another network connection?
             */
            AFLOG_INFO("cm_select_next_inuse_network:: DOWN/NO_IP event, trigger_ev_conn_p=%p, inuse_p=%p",
                       trigger_ev_conn_p, inuse_p);

            if (trigger_ev_conn_p == inuse_p) {
                int   i;
                int   want_status=(trigger_ev > NETCONN_STATUS_ITFNOTSUPP_SX) ? trigger_ev:NETCONN_STATUS_ITFNOTSUPP_SX;

                // Switch to another network connection - which one?
                AFLOG_INFO("cm_select_next_inuse_network:: Current INUSE network (%s) went down",
                           trigger_ev_conn_p->dev_name);
                AFLOG_INFO("cm_select_next_inuse_network::   Looking for network with status=(%d-%s)",
                           want_status, NETCONN_STATUS_STR[want_status]);
                for (i=0; i<CONNMGR_NUM_MONITORED_ITF; i++) {
                    // found the first Available interface to assign
                    if ((selected_p == NULL) &&
                        (cm_monitored_net[i].dev_link_status > want_status)) {
                        selected_p = &cm_monitored_net[i];
                    }

                    if  ((selected_p) && (cm_monitored_net[i].conn_active)) {
                        /* The designated 'select' network is not active, and this one is.
                         * Use the active network
                         */
                        if (selected_p->conn_active == 0) {
                            selected_p = &cm_monitored_net[i];
                        }
                        else {
                            // make the selection based on link_status first, then priority
                            if (selected_p->dev_link_status < cm_monitored_net[i].dev_link_status) {
                                // selected_p connection is also active, which one has a higher priority
                                if (selected_p->mon_policy.priority > cm_monitored_net[i].mon_policy.priority) {
                                    selected_p = &cm_monitored_net[i];
                                }
                            }
                        }
                    }

                }  // for
            }
            else
            {
                /* the 'down' network is not passing traffic, no need to do anything */
                AFLOG_DEBUG1("cm_select_next_inuse_network:: Network (%s) not INUSE, contiue with (%s)",
                             trigger_ev_conn_p->dev_name,
                             ((inuse_p != NULL) ? ((char *)inuse_p->dev_name) : "NULL"));
                selected_p = inuse_p;
            }
            break;

    default:
        break;
    }

    /* if the algorithm couldn't select one, let's stick with the previous INUSE */
    if (selected_p == NULL) {
        AFLOG_DEBUG1("cm_select_next_inuse_network:: No new selection. Use the current network");
        selected_p = inuse_p;
    }
    AFLOG_INFO("cm_select_next_inuse_network:: Selected dev=%s, switch/refresh route",
               ((selected_p != NULL) ? (selected_p->dev_name) : "NULL") );

    return selected_p;
}


/* wrap function to call cm_select_inuse_network */
int
cm_check_update_inuse_netconn(hub_netconn_status_t    trigger_ev,
                              cm_conn_monitor_cb_t    *trigger_ev_conn_p)
{
    cm_conn_monitor_cb_t  *switch_to_p = NULL;
    cm_conn_monitor_cb_t  *cur_inuse_p = CM_GET_INUSE_NETCONN_CB();
    uint32_t   rc;


    if ((trigger_ev_conn_p == NULL) ||
        (trigger_ev < 0) || (trigger_ev >= NETCONN_STATUS_MAX )) {
        AFLOG_ERR("cm_check_update_inuse_netconn:: Invalid input, trigger_ev=%d, ptr=%p",
                    trigger_ev, trigger_ev_conn_p);
        return (0);
    }

    AFLOG_DEBUG2("cm_check_update_inuse_netconn:: trigger_ev=%d(%s), trigger_ev_conn_p=%p, cur_inuse_p=%p",
               trigger_ev, NETCONN_STATUS_STR[trigger_ev],
               trigger_ev_conn_p, cur_inuse_p);

    switch_to_p = cm_select_next_inuse_network(trigger_ev, trigger_ev_conn_p);
    if (switch_to_p == NULL) {
        AFLOG_INFO("cm_check_update_inuse_netconn:: No selection made. Continue with current NETWORK (%s)",
                   ((cur_inuse_p == NULL) ? "NULL" : (cur_inuse_p->dev_name)) );
        return (0);   // not updated
    }
    if (switch_to_p == cur_inuse_p) {  /* We don't want to update the route */
        AFLOG_INFO("cm_check_update_inuse_netconn:: Continue to use current NETWORK (%s)",
                   ((cur_inuse_p == NULL) ? "NULL" : (cur_inuse_p->dev_name)) );
		goto DONE_SWITCHING;
    }


    AFLOG_INFO("cm_check_update_inuse_netconn:: Switch to network - %s", switch_to_p->dev_name);

    // Else - update to the selected network
    if (switch_to_p->pcap_handle == NULL) {
		/* under normal condition, the pcap_handle should not be NULL (when this
		 * network connection is selected).
		 *
		 * However, if user restart the network(i.e on the console), this could happen.
		 * (when all the network interfaceis went down, and then restarted)
		 * */
        if (switch_to_p->conn_init_func) {
            int   old_link_status = switch_to_p->dev_link_status;

            if (switch_to_p->conn_init_func(CONNMGR_GET_EVBASE(), switch_to_p) > 0) {
                /* update the link status and increment monitored network counter */
                cm_set_itf_up(switch_to_p, NETCONN_STATUS_ITFUP_SU);

                // TODO -- notify
                AFLOG_INFO("cm_mon_tmout_handler:: Notify, dev=%s, link_status changed:(%d - %s)",
                           switch_to_p->dev_name,
                           old_link_status, NETCONN_STATUS_STR[old_link_status]);
                AFLOG_INFO("cm_mon_tmout_handler::     -> (%d, %s)",
                           switch_to_p->dev_link_status, NETCONN_STATUS_STR[switch_to_p->dev_link_status]);
            }
        }
    }


    if (switch_to_p->conn_timer_event) {
            evtimer_add(switch_to_p->conn_timer_event, &switch_to_p->mon_tmout_val);
    }
    else {
            AFLOG_WARNING("cm_check_update_inuse_netconn:: WARNING, no conn_timer_event");
    }


DONE_SWITCHING:
	if (cur_inuse_p != switch_to_p) {
		/* Update the stats for the previous INUSE network conn */
		if (cur_inuse_p != NULL) {
			connmgr_usage_stats_update_end_tm(cur_inuse_p->my_idx);
		}

		/* Update the stats for newly INUSE network */
		connmgr_mon_increment_netmon_switch_stat(switch_to_p->my_idx);
		connmgr_usage_stats_update(switch_to_p->my_idx);

		/* update the routes */
		rc = af_util_system("/usr/bin/switch_route_to.sh %s", switch_to_p->dev_name);
		if (rc < 0) {
			AFLOG_ERR("cm_check_update_inuse_netconn:: ROUTE SWITCHING TO NETWORK(%s) failed",
					switch_to_p->dev_name);
		}

		AFLOG_INFO("cm_check_update_inuse_netconn:: SWITCHED from (%s) to NETWORK(%s, active=%d)",
					((cur_inuse_p == NULL) ? "NULL" : (cur_inuse_p->dev_name)),
					switch_to_p->dev_name, switch_to_p->conn_active);

		CM_SET_INUSE_NETCONN_CB(switch_to_p);


	}
	else {
		AFLOG_INFO("cm_check_update_inuse_netconn:: Selected dev=%s already INUSE, NO SWITCH",
				   switch_to_p->dev_name);
	}

    // hubby uses the network type, let's send the notify so hubby gets it
    cm_attr_set_network_type();

    /* delay updating the attributes until we know the network passing traffic */
    CONNMGR_SET_ATTR_PENDING(1);

    /* log the stats */
    connmgr_log_stats(switch_to_p->dev_name, switch_to_p->my_idx);

    return (1);
}
