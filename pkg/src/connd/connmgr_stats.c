/*
* connmgr_stat.c
*
* - collect connection statistics: number of rx packets, number of tx packets
*   etc.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <stddef.h>
#include <syslog.h>
#include <event.h>
//#include <linux/if.h>

#include "connmgr.h"
#include "connmgr_stats.h"
#include "af_log.h"

/* file contains info about the configured network interfaces, including
 * statistics.  We are going to read the TX and RX bytes from it.
 */
#define  PATH_PROC_NET_DEV    "/proc/net/dev"


#define CONNMGR_MONITORED_ITF_ETH       CM_MONITORED_ETH_IDX
#define CONNMGR_MONITORED_ITF_WLAN      CM_MONITORED_WLAN_IDX
#define CONNMGR_MONITORED_ITF_WAN       CM_MONITORED_WAN_IDX

static  cm_stats_t  cm_stats_db[CONNMGR_NUM_MONITORED_ITF];


/* internal routine to get the network interface stats
 *
 * root@OpenWrt:~# cat /proc/net/dev
 * Inter-|   Receive                                                |  Transmit
 *  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
 *  wwan1:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
 *     lo:  100982     986    0    0    0     0          0         0   100982     986    0    0    0     0       0          0
 *  wwan0:    1618      15    0    0    0     0          0         0     3896      13    0    0    0     0       0          0
 *  wlan0: 5120680   44537    0    0    0     0          0         0   154637    1605    0    0    0     0       0          0
 *  wwan3:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
 *   eth0:  698861    3713    0    0    0     0          0         0     1718      11    0    0    0     0       0          0
 *  wwan2:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
 * br-lan:  646879    3713    0    0    0     0          0         0     1718      11    0    0    0     0       0          0
 */
static void
connmgr_get_ifstats (const char *dev_name, uint8_t idx) {
    FILE *fp = fopen(PATH_PROC_NET_DEV, "r");
    char buf[256];
    char *ptr = NULL;
    char name[IFNAMSIZ];
    unsigned long rx_bytes, rx_packets, rx_errs, rx_drops, rx_fifo, rx_frame, rx_multi,
            tx_bytes, tx_packets, tx_errs, tx_drops, tx_fifo, tx_colls, tx_carrier;


    if (fp == NULL) {
        AFLOG_ERR("connmgr_get_ifstats::fopen (%s) failed", PATH_PROC_NET_DEV);
        return;
    }
    if (dev_name == NULL) {
        AFLOG_ERR("connmgr_get_ifstats:: Invalid input dev name");
        goto end_get_stats;
    }
    if ((idx < 0) || (idx > CONNMGR_NUM_MONITORED_ITF)) {
        AFLOG_ERR("connmgr_get_ifstats:: Invalid idx: %d", idx);
        goto end_get_stats;
    }

    /* skip first two lines (or the headers) at the beginning of the file */
    if ( (!fgets(buf, sizeof(buf), fp)) ||
         (!fgets(buf, sizeof(buf), fp)) ) {
        goto end_get_stats;
    }

    memset(buf, 0, sizeof(buf));
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        if ((ptr = strchr(buf, ':')) == NULL ||
            (*ptr++ = 0, sscanf(buf, "%16s", name) != 1)) {
            // fprintf(stderr, "Wrong format for /proc/net/dev. Giving up.\n");
            goto end_get_stats;
        }

        if (strcmp(name, dev_name) == 0) {
            AFLOG_DEBUG2("connmgr_get_ifstats:: ifname=%s", name);

            if (sscanf(ptr, "%lu%lu%lu%lu%lu%lu%lu%*d%lu%lu%lu%lu%lu%lu%lu",
                       &rx_bytes, &rx_packets, &rx_errs, &rx_drops,
                       &rx_fifo, &rx_frame,  &rx_multi,
                       &tx_bytes, &tx_packets, &tx_errs, &tx_drops,
                       &tx_fifo, &tx_colls, &tx_carrier) == 14) {
                cm_stats_db[idx].traffic_stats.rx_bytes = rx_bytes;
                cm_stats_db[idx].traffic_stats.rx_packets = rx_packets;
                cm_stats_db[idx].traffic_stats.rx_drops = rx_drops;
                cm_stats_db[idx].traffic_stats.rx_errs  = rx_errs;
                cm_stats_db[idx].traffic_stats.rx_fifo  = rx_fifo;
                cm_stats_db[idx].traffic_stats.rx_frame = rx_frame;

                cm_stats_db[idx].traffic_stats.tx_bytes   = tx_bytes;
                cm_stats_db[idx].traffic_stats.tx_packets = tx_packets;
                cm_stats_db[idx].traffic_stats.tx_drops   = tx_drops;
                cm_stats_db[idx].traffic_stats.tx_errs    = tx_errs;
            }

        }
    }

    end_get_stats:

        if(fp) {
            fclose(fp);
        }

    return;
}

/* connmgr_stats_db_init
 * Initialize all the counters in the cm_stats_db
 * */
void
connmgr_stats_db_init ()
{
    int     i;

    // initialize the WAN usage statistics database
    for (i=0; i<CONNMGR_NUM_MONITORED_ITF; i++) {
        cm_stats_db[i].usage_stats.inuse_count    = 0;
        cm_stats_db[i].usage_stats.inuse_start_tm = 0;
        cm_stats_db[i].usage_stats.inuse_end_tm   = 0;

        memset(&cm_stats_db[i].traffic_stats, 0, sizeof(cm_traffic_stats_t));
        memset(&cm_stats_db[i].mon_stats, 0, sizeof(cm_mon_stats_t));
    }
    return;
}


/****
 * MONITOR STATS
 */
void
connmgr_mon_stats_reset (uint8_t idx)
{
    if ((idx >= 0) && (idx <CONNMGR_NUM_MONITORED_ITF)) {
        // initialize the monitor statistics block data
        cm_stats_db[idx].mon_stats.num_of_pings = 0;
        cm_stats_db[idx].mon_stats.netconn_switch_count = 0;
    }
    return;
}

/* increment the monitor_stats.num_of_ping by 1
 */
void connmgr_mon_increment_ping_stat(uint8_t  idx)
{
    if ((idx >= 0) && (idx <CONNMGR_NUM_MONITORED_ITF)) {
        cm_stats_db[idx].mon_stats.num_of_pings++;
    }
}

void connmgr_mon_increment_netmon_switch_stat(uint8_t idx)
{
    /* Number of time that we switched to this network conn */
    if ((idx >= 0) && (idx <CONNMGR_NUM_MONITORED_ITF)) {
        cm_stats_db[idx].mon_stats.netconn_switch_count++;
    }
}


/**********************/
/*   usage stats      */
/**********************/

/* connmgr_usage_stats_update
 *
 * Increment the usage_stats
 *  - update the time when interface pointed to via this idx started to be INUSE
 */
void
connmgr_usage_stats_update(uint8_t  idx)
{
    if ((idx >= 0) && (idx <CONNMGR_NUM_MONITORED_ITF)) {
        cm_stats_db[idx].usage_stats.inuse_start_tm = time(NULL);
        cm_stats_db[idx].usage_stats.inuse_count++;
    }
}


void
connmgr_usage_stats_update_end_tm(uint8_t   idx)
{
    if ((idx >= 0) && (idx <CONNMGR_NUM_MONITORED_ITF)) {
        cm_stats_db[idx].usage_stats.inuse_end_tm = time(NULL);
    }
}


/**********************/
/*   log stats        */
/**********************/

/* connmgr_log_stats
 * Log the statistics for a given interface (per idx)
 */
void
connmgr_log_stats(const char *dev_name, uint8_t idx)
{
    cm_conn_monitor_cb_t *inuse_p = CM_GET_INUSE_NETCONN_CB();
	char    tm_buf[60];

    if (inuse_p) {
        AFLOG_DEBUG1("INUSE network: %s", inuse_p->dev_name);
    }
    AFLOG_DEBUG1("Num of active networks: %d", cm_netconn_count);

    if ((idx >= 0) && (idx <CONNMGR_NUM_MONITORED_ITF)) {
        AFLOG_DEBUG1("Monitor statistics for (%s):", dev_name);
        AFLOG_DEBUG1("    num_of_pings: %d", cm_stats_db[idx].mon_stats.num_of_pings);
        AFLOG_DEBUG1("    switched_counter: %d", cm_stats_db[idx].mon_stats.netconn_switch_count);

        AFLOG_DEBUG1("Usage statistics for (%s):", dev_name);
        AFLOG_DEBUG1("    inuse_count: %d", cm_stats_db[idx].usage_stats.inuse_count);

        /* Convert to local time format. */
        memset(tm_buf, 0, sizeof(tm_buf));
        ctime_r(&cm_stats_db[idx].usage_stats.inuse_start_tm, tm_buf);
        AFLOG_DEBUG1("    inuse_start_tm: %s",
                     ( (cm_stats_db[idx].usage_stats.inuse_start_tm == 0) ?
                        "--" : tm_buf));
        memset(tm_buf, 0, sizeof(tm_buf));
        ctime_r(&cm_stats_db[idx].usage_stats.inuse_end_tm, tm_buf);
        AFLOG_DEBUG1("    inuse_end_tm  : %s",
                     ((cm_stats_db[idx].usage_stats.inuse_end_tm == 0) ?
                        "--" : tm_buf ));

        /* refresh the traffic stats before printing it out */
        connmgr_get_ifstats(dev_name, idx);

        AFLOG_DEBUG1("  Transmission stats since system up:");
        AFLOG_DEBUG1("    rx_bytes: %d  rx_packets: %d  rx_drops: %d  rx_errs: %d",
                     cm_stats_db[idx].traffic_stats.rx_bytes,
                     cm_stats_db[idx].traffic_stats.rx_packets,
                     cm_stats_db[idx].traffic_stats.rx_drops,
                     cm_stats_db[idx].traffic_stats.rx_errs);
        AFLOG_DEBUG1("    tx_bytes: %d  tx_packets: %d  tx_drops: %d  tx_errs: %d",
                     cm_stats_db[idx].traffic_stats.tx_bytes,
                     cm_stats_db[idx].traffic_stats.tx_packets,
                     cm_stats_db[idx].traffic_stats.tx_drops,
                     cm_stats_db[idx].traffic_stats.tx_errs);
    }
    return;
}


/*
* connmgr_get_data_usage_cb
*
* given an interface index, returns the stats cb pointer.
*/
cm_stats_t *connmgr_get_data_usage_cb(uint8_t  idx)
{
    if (idx == CONNMGR_MONITORED_ITF_ETH) {
        connmgr_get_ifstats(CONNMGR_ETH_IFNAME, idx);
        return (&cm_stats_db[idx]);
    }
    else if (idx == CONNMGR_MONITORED_ITF_WLAN) {
        connmgr_get_ifstats(CONNMGR_WLAN_IFNAME, idx);
        return (&cm_stats_db[idx]);
    }
    else if (idx == CONNMGR_MONITORED_ITF_WAN) {
        connmgr_get_ifstats(CONNMGR_WAN_IFNAME, idx);
        return (&cm_stats_db[idx]);
    }
    else {
        return NULL;
    }
}
