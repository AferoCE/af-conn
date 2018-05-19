/*
* hub_config.c
*
* This contains the definition and implementation of utilities about 
* the hub(bento) configuration (required by daemon managing connectivitiy).
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
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "af_log.h"
#include "../include/hub_config.h"


/* default to production environment */
uint8_t    is_env_on_prod = 1;

const char *conclave_service_host_p = PROD_CONCLAVE_HOST;
const char *echo_service_host_p     = PROD_ECHO_HOST;


/*
 * Internal routine to read the service config file update
 * the environment variables accordingly.
 */
static void
hub_config_set_service_hosts ()
{
	FILE        *fp = NULL;
    char        line[80];


   /* open the file to read only */
    fp = fopen(HUB_SERVICE_CONFIG_FILE, "r");
    if (fp == NULL) {
        AFLOG_INFO("hub_config_service_host:File(%s) doesn't exist, on PROD", HUB_SERVICE_CONFIG_FILE);
        return;
    }

	/* we know that the service file only contain one line */
    while (fgets(line, sizeof(line), fp) != NULL) {
		if (strcasestr(line, ".dev") != NULL) {
		   conclave_service_host_p = DEV_CONCLAVE_HOST;
           echo_service_host_p     = DEV_ECHO_HOST;

           is_env_on_prod = 0;

		   break;
		}
	}

	AFLOG_INFO("hub_config_service_host: echo=%s",
				(echo_service_host_p == NULL) ? "" : echo_service_host_p);
	AFLOG_INFO("hub_config_service_host: conclave=%s",
				(conclave_service_host_p == NULL) ? "" : conclave_service_host_p);

	/* The file exists */
	fclose (fp);
}


/* hub_config_service_env_init
 *
 * Init function to set the host env related variables.
 * - attributes are set to different value depending on whether
 *   the service env is set to dev or prod
 */
void hub_config_service_env_init () 
{
     hub_config_set_service_hosts();

}
