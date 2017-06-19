/*
 * connmgr_stats.h
 *
 * This contains definitions for managing statistics.
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */

#ifndef CONND_CONNMGR_STATS_H
#define CONND_CONNMGR_STATS_H

// what kind of statistics do we want to track??
//
typedef struct {
    uint32_t        netconn_switch_count;  //total num of network switch happened
    uint32_t        num_of_pings;
} cm_mon_stats_t;

typedef struct  {
    /* Receiving stats */
    uint32_t    rx_bytes;
    uint32_t    rx_packets;
    uint32_t    rx_errs;
    uint32_t    rx_drops;
    uint32_t    rx_fifo;
    uint32_t    rx_frame;

    /* transmission stats */
    uint32_t    tx_bytes;
    uint32_t    tx_packets;
    uint32_t    tx_errs;
    uint32_t    tx_drops;
} cm_traffic_stats_t;

/* WAND statistics */
typedef struct {
    uint32_t    inuse_count;
    time_t      inuse_start_tm;
    time_t      inuse_end_tm;
} cm_usage_stats_t;

/* 
 * connmgr stats
 */
typedef struct cm_stats_ {
    cm_mon_stats_t      mon_stats;
    cm_traffic_stats_t  traffic_stats;
    cm_usage_stats_t    usage_stats;
} cm_stats_t;


/* initialize all the stats counters
 */
extern void connmgr_stats_db_init ();

/* cm_stats_cb[i].mon_stats */
extern void connmgr_mon_stats_reset(uint8_t idx);
extern void connmgr_mon_increment_ping_stat(uint8_t idx);
extern void connmgr_mon_increment_netmon_switch_stat(uint8_t idx);


/* cm_stats_cb[i].usage_stats */
extern void connmgr_usage_stats_update(uint8_t idx);
extern void connmgr_usage_stats_update_end_tm(uint8_t idx);


/* to logs the stats per interface*/
extern void connmgr_log_stats (const char *dev_name, uint8_t idx);

#endif //CONND_CONNMGR_STATS_H