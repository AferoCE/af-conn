/*
* hub_config.h
*
* This contains the definition and implementation of utilities about 
* the hub(bento) configuration (required by daemon managing connectivitiy).
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#ifndef _HUB_CONFIG_H_
#define _HUB_CONFIG_H_


/* constants related the AFERO serivce environment */
#define HUB_SERVICE_CONFIG_FILE     "/etc/config/afero_whitelist.txt"

#define PROD_CONCLAVE_HOST          "conclave.afero.io"
#define DEV_CONCLAVE_HOST           "conclave.dev.afero.io"

#define PROD_ECHO_HOST              "echo.afero.io"
#define DEV_ECHO_HOST               "echo.dev.afero.io"

#define ECHO_SERVICE_PORT          80


/* Depending on the environment, the host pointers  
 * either points to their production hosts or the 
 * dev hosts.
 */ 
extern const char *conclave_service_host_p;
extern const char *echo_service_host_p;


/* based on the service file - this ether set to  
 *  0 = NOT on prod environment, on dev environment  
 *  1 = it is on prod environment 
 */
extern uint8_t    is_env_on_prod;



/* API to set the above environment based variables */
extern 
void hub_config_service_env_init ();


/*
 *  TODO - we might want to find a better place.  For now.
 */
extern uint32_t           cm_wifi_opmode;

extern uint32_t
hub_wireless_opmode(const char *ifname);

#endif //_HUB_CONFIG_H_
