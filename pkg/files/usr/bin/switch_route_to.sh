#!/bin/sh

# Manage the default route entries based on the connmgr daemon's
# INUSE network selection.  The INUSE network refers to the highest
# priority, connected network that bento uses for passing traffic.
#
# There are potentially three different network interfaces:
# - ethernet (eth0 ), when supported
# - wireless (wlan0), when supported
# - LTE wan  (wwan0), when supported
#
# The connmgr daemon actively monitors the first two
# interfaces (ethernet, wireless) and ping the echo server
# periodically when its idle count is reached. And the design
# assumes that LTE WAN is always connected and it is our backup
# network (when it is supported on the bento).  We don't actively
# monintor the WAN interface because it costs money.
#
# Based on the priority, and network connectivity,
# the connmgr daemon selects the appropriate network interface
# to be the 'default' traffic passing network.
#
# To enable the 'selected' network as the default traffic passing
# network interface: we utilize the route in the routing table to do so.
#
# As a default config, we can assign a metric to the default route for each
# network interface. And the default metric value is higher than zero (0).
#
# When an network interface is selected to be the INUSE network,
# we will change its default route metric to zero 0.  Otherwise,
# its route metric value is set to 'default configured' metric
# value.
#

#default route metrics values.
#Note:
#  The values should match the default values used in the config files
#  (see /etc/config/network, and wand daemon)
#
DEFAULT_ETH_ROUTE_METRIC=10
DEFAULT_WLAN_ROUTE_METRIC=20
DEFAULT_WWAN_ROUTE_METRIC=50

IP_ADDR=""
GATEWAY=""
METRIC=-1

USE_WIFI=0
USE_ETH=0
USE_WAN=0

ROUTE_TABLE=""

# Get the names of the network interfaces
. /lib/afero_get_netif_names

# The script takes an input: a network interface name,
# Check to make sure the ifname is one of the network interface that
# we support.
[ $# -ge 1 ] && input_name="$1"
if [ -n "$input_name" ]; then

	ifname=$input_name
	if [ "$ifname" == "${WIFISTA_INTERFACE_0}" ]; then
		USE_WIFI=1
	elif [ "$ifname" == "${WAN_INTERFACE_0}" ]; then
		USE_WAN=1
	elif [ "$ifname" == "${ETH_INTERFACE_0}" ]; then
		USE_ETH=1
	else
	   echo "Invalid ifname -$ifname"
	   exit 1
	fi

else
	echo "no ifname -$ifname"
	exit 1
fi
echo "switch_to_route:dev_name=$input_name, USE_WIFI=$USE_WIFI, USE_ETH=$USE_ETH"


# make a copy of the routing table
ROUTE_TABLE=`route -n`

#echo "We have a copy of the route table:  "
#echo "$ROUTE_TABLE"


get_route_metric()
{
	local itf_name=$1

	if [ "x${itf_name}x" = "x${ETH_INTERFACE_0}x" ] ; then
		return $DEFAULT_ETH_ROUTE_METRIC
	elif [ "x${itf_name}x" = "x${WIFISTA_INTERFACE_0}x" ] ; then
		return $DEFAULT_WLAN_ROUTE_METRIC
	elif [ "x${itf_name}x" = "x${WAN_INTERFACE_0}x" ] ; then
		return $DEFAULT_WWAN_ROUTE_METRIC
	else
		return 0
	fi
}

#
# Get the ip address for the input network interface dev
#
query_ip_addr()
{
	local itf_name=$1
    local result=`ifconfig $itf_name | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}'`

    if [ -n "$result" ]; then
        IP_ADDR=$result
    else
        IP_ADDR=""
        echo "$itf_name ip addr is not set"
		logger "switch_route_to: Error, input_dev=$itf_name, no ip found"
    fi
}


#
# Get the gateway for the input network interface dev
#
query_gateway()
{
	local itf_name=$1
    local result=`route -n | grep $itf_name | awk 'NR==1 && $1=="0.0.0.0" {print $2}'`
    if [ -n "$result" ]; then
        GATEWAY=$result
    else
        GATEWAY=""
        echo "Error: $itf_name gateway is not set"
        logger "switch_to_route:Error: $itf_name gateway is not set"
    fi
}


# 
# Not used for now
# (Will remove before production if we don't have a use for it)
set_wlan_metric()
{

    echo "Setting wlan0 metric to $metric..."

    # Remove all default routes for wlan0 interface
    local count=`route -n | grep wlan0 | awk '$1=="0.0.0.0"'{print} | wc | awk '{print $1}'`
    while [ $count -gt 0 ]; do
        echo "route del -net default dev wlan0"
        route del -net default dev wlan0
        count=`expr $count - 1`
    done

    echo "route add -net default gw $GATEWAY dev wlan0 metric $metric"
    route add -net default gw $GATEWAY dev wlan0 metric $metric

    rm /etc/resolv.conf
    if [ $metric -eq 0 ]; then
        ln -s /tmp/resolv.conf /etc/resolv.conf
    else
        ln -s /tmp/resolv.conf_wan /etc/resolv.conf
    fi

    echo "Successfully set wlan0 metric to $metric!"
    METRIC=$metric
}

#
# For the given input interface itf_name, 
# added the default route with metric 0 
# 
add_default_route()
{
	local itf_name=$1
	if [ -z "$itf_name" ]; then
		exit 1
	fi

    logger "swtich_to_route: route add -net default gw $GATEWAY dev $itf_name metric 0"
    echo "switch_to_route: route add -net default gw $GATEWAY dev $itf_name metric 0"

	# 
	# adding the route 
    route add -net default gw $GATEWAY dev $itf_name metric 0 
}


#
# delete all the default routes with metric zero 
# 
delete_default_route_with_metric_zero()
{
	local itf_name=$1

	# using route -n to get a list of default routes
    # get the routes with metric == 0, and the print its dev name
	local dev_name_list=`route -n | awk '$5 == 0'| awk '$2 != "0.0.0.0"' | awk '{print $8};'`

	#
    #for each dev interface we found in the route table (with metric==0) 
    #
    for dev_name in $dev_name_list;
    do
		if [ "$itf_name" != "$dev_name" ]; then 
			logger "switch_route_to: dev=$dev_name, delete existing default route with metric 0"
			echo "switch_route_to: dev=$dev_name, delete existing default route with metric 0"

			route del -net default dev $dev_name metric 0
		fi 
	done
}


# 
# Perform a sanity check on the route table, and check each 
# subnet has a route other than default route with metric zero
#
route_sanity_check_and_fix()
{
	# using route -n command to get the entries from the route table
    # get the entries with the gateway == 0.0.0.0 (i.e specific subnet entries)
    # 
    # get an unique list of the device name from the subnet entries list.
    #
	local dev_name_list=`route -n | awk '$2 == "0.0.0.0"'| awk '{print $8};' | uniq`
	
	#for each name in the above list
    #  we want to make sure that there is a default route with the 
    #  the default metric value
    for dev_name in $dev_name_list;
    do
	
		local route_count=`route -n | grep $dev_name | awk '$1=="0.0.0.0"' | wc -l`
		if [ $route_count -le 0 ]; 
		then
			#
			# we don't find any route for this interface, something is wrong.
			# At this point, we don't have the gw info. To fix it: restart the network
            # (a bit drastic, but this takes us back to the default config routes 
			#
			logger "switch_route_to: For dev=$dev_name, failed SANITY "
			echo "switch_route_to: For dev=$dev_name, failed SANITY "

			#echo `echo "$ROUTE_TABLE" | grep "$dev_name" |awk 'NR==1 && $1=="0.0.0.0" {print $2}'`
			local this_gateway=`echo "$ROUTE_TABLE" | grep "$dev_name" |awk 'NR==1 && $1=="0.0.0.0" {print $2}'`

			get_route_metric $dev_name
			this_metric=$?

			echo "switch_route_to:    gw=$this_gateway, metric=$this_metric"
			if [ -n "$this_gateway" ] && [ $this_metric -gt 0 ]; 
			then
				echo "switch_route_to:    dev=$dev_name, Add a default route with metric $this_metric"
				logger "switch_route_to:    dev=$dev_name, Add a default route with metric $this_metric"

				route add -net default gw $this_gateway dev $dev_name metric $this_metric	
			else 
				logger "switch_route_to:     dev=$dev_name, NOT ABLE TO FIX ROUTE"
				echo "switch_route_to:    dev=$dev_name, NOT ABLE TO FIX ROUTE" 
			fi 
		else 
			logger "switch_route_to: For dev=$dev_name, route sanity check Ok"
			echo "switch_route_to: For dev=$dev_name, route sanity check OK"
		fi
	done 
}


update_dns_resolv()
{
    local result=`ls -l /etc/resolv.conf | grep wan`
    if [ -n "$result" ]; then
        # currently using wan resolv.conf
        if [ "$USE_WIFI" -eq 1 ]; then
            # switch to wifi resolv.conf
            echo "switching to /tmp/resolv.conf"
            rm /etc/resolv.conf
            ln -s /tmp/resolv.conf /etc/resolv.conf
            echo 1 | nc localhost:12345
        fi
    else
        # currently using wifi resolv.conf
        if [ "$USE_WIFI" -eq 0 ]; then
            echo "switching to /tmp/resolv.conf_wan"
            rm /etc/resolv.conf
            ln -s /tmp/resolv.conf_wan /etc/resolv.conf
            echo 1 | nc localhost:12345
        fi
    fi
}

main()
{
#        update_dns_resolv

        # Check if IP address is set (for the input interface)
        query_ip_addr $input_name
        if [ -z "$IP_ADDR" ] ; then
			exit 1
        fi
		echo "IP_ADDR=$IP_ADDR, USE_WIFI=$USE_WIFI, USE_ETH=$USE_ETH"

        # Check if gateway is set.  
		# Note: if no ip address or gateway, then wifi is not working 
        # properly.  This means we should not switch to WIFI 
        query_gateway $input_name
        if [ -z "$GATEWAY" ]; then
			logger "switch_route_to: Error, dev=$input_name, NO GATEWAY FOUND"
			exit 1
        fi
		echo "GATEWAY=$GATEWAY, USE_WIFI=$USE_WIFI, USE_ETH=$USE_ETH"
		logger "switch_route_to:IP_ADDR=$IP_ADDR, GW=$GATEWAY, USE_WIFI=$USE_WIFI, USE_ETH=$USE_ETH"
		

		# delete the default route with zero metric 
		delete_default_route_with_metric_zero $input_name

		# sanity check on the route (and recovery fix: restart network)
		route_sanity_check_and_fix

		# add a default route
		#
		add_default_route $input_name
}

main
