/*
 * hub_wifi_config.c
 *
 * This contains the definition and implementation of utilities about
 * the hub(bento) configuration (required by daemons managing
 * connectivitiy).
 *
 * Copyright (c) 2016-present, Afero Inc. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
char *strcasestr(const char *haystack, const char *needle);
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <syslog.h>
#include <event.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/wireless.h>

#include "connmgr_hub_opmode.h"
#include "af_log.h"


// only define the ones we are using
const char *HUB_WIFI_OPMODE_NAMES[] = {
    "Unknown",
    "Master",
    "Ad-Hoc",
    "Client",
    "Monitor",
};


/* hub_wireless_opmode
 *
 * Return the operation mode of the specified wireless network interface.
 *
 * Note:
 * This is somewhat 'platform dependent'(i.e the os must set the wireless opmode).
 *
 * Mar 22, 2017:
 * The original design intend was to use OPMODE to see if the HUB operates
 * as an AP. Currently, we don't support the AP mode.
 *
 */
uint32_t
hub_wireless_opmode(const char *ifname)
{
	int   sockfd = -1;
	struct iwreq wrq;
	int   rc;
	int   opmode = HUB_WIFI_OPMODE_UNKNOWN;


	if ((ifname == NULL) || (strlen(ifname) > IFNAMSIZ)) {
		AFLOG_INFO("hub_wireless_opmode: invalid ifname");
		return 0;
	}

 	// open the socket and prepare it
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		AFLOG_INFO("hub_wireless_opmode: socket failed");
		return 0;
	}
	fcntl(sockfd, F_SETFD, fcntl(sockfd, F_GETFD) | FD_CLOEXEC);

	// cmd = SIOCGIWMODE - get operation mode
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);
	rc = ioctl(sockfd, SIOCGIWMODE, (void *)&wrq);

	if (rc >= 0) {
		switch(wrq.u.mode) {
			case IW_MODE_ADHOC:  // 1
				opmode = HUB_WIFI_OPMODE_ADHOC;
				break;

			case IW_MODE_INFRA:  // 2
				opmode = HUB_WIFI_OPMODE_CLIENT;
				break;

			case IW_MODE_MASTER: // 3
				opmode = HUB_WIFI_OPMODE_MASTER;
				break;

			case 6:
				opmode = HUB_WIFI_OPMODE_MONITOR;
				break;

			case IW_MODE_REPEAT:
				default:
				opmode = HUB_WIFI_OPMODE_UNKNOWN;
				break;
        }
	}


	AFLOG_DEBUG2("hub_wireless_opmode:: wrq.u.mode=%d, opmode=%d", wrq.u.mode, opmode);
	AFLOG_INFO("hub_wireless_opmode:: wifi operation mode on (%s) %s",
				ifname, HUB_WIFI_OPMODE_NAMES[opmode]);

	// close the socket
	close(sockfd);
	return (opmode);
}
