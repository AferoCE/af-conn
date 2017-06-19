/*
* echo.c
*
* This contains the code implementation utilities or helper functions.
*
* Copyright (c) 2016-present, Afero Inc. All rights reserved.
*/

#include <stdio.h>
#include <errno.h>
#ifndef _GNU_SOURCE 
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#endif 
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
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/netlink.h>    // netlink - hotplug

#include "af_log.h"
#include "../include/hub_config.h"

#define   PRINT_ITF_STRING(itf)     ( (itf == NULL) ? "N/A" : itf )

const char  *PING_ADDR = "8.8.8.8";


/*
 * in_cksum --
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 * -- from the "open source"
 */
unsigned
short in_cksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;


    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);       /* add hi 16 to low 16 */
    sum += (sum >> 16);                       /* add carry */
    answer = ~sum;                            /* truncate to 16 bits */
    return (answer);
}


/* Internal help function to send a ping request and get a reply */
int conn_prv_ping(const char *src_addr, const char *dst_addr, const char *itf_string) {
    int packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr);
    uint8_t packet[packet_size];
    uint8_t buffer[128];
    struct iphdr *ip;
    struct icmphdr *icmp;
    int sockfd = -1;
    char *src_addr_p = (char *) src_addr;
    char *dst_addr_p = (char *) dst_addr;
    struct sockaddr_in from;
    uint32_t addrlen;
    int result;
    int optval;
    int counter = 0;

    if ((src_addr == NULL) || (dst_addr == NULL) || (itf_string == NULL)) {
        AFLOG_ERR("conn_prv_ping:: Invalid input addr or interface:src=%s, dest=%s, itf=%s",
                  src_addr, dst_addr, itf_string);
        return (0);
    }

    if (getuid() != 0) {
        AFLOG_ERR("conn_prv_ping:: getuid failed");
        return (0);
    }
    memset(packet, 0, sizeof(packet));

    ip = (struct iphdr *) &packet[0];
    icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

    /** setup the ip packet,  except checksum  */
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->id = htons(random());
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr(src_addr_p);
    ip->daddr = inet_addr(dst_addr_p);

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        AFLOG_ERR("PRV_PING:: socket failed");
        return (0);
    }

    /* tell the kernel to automatically tag on a IP header */
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = random();
    icmp->un.echo.sequence = 0;
    icmp->checksum = 0;
    icmp->checksum = in_cksum((unsigned short *) icmp, sizeof(struct icmphdr));

    ip->check = in_cksum((unsigned short *) ip, sizeof(struct iphdr));

    from.sin_family = AF_INET;
    from.sin_addr.s_addr = inet_addr(dst_addr_p);

    /* using an specific interface */
    if (itf_string != NULL) {
        result = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, itf_string, IFNAMSIZ - 1);
        if (result < 0) {
            AFLOG_DEBUG1("conn_prv_ping:: setopt SO_BINDTODEVICE failed ");
			close(sockfd);
            return (0);
        }
    }

    /* tell the kernel that the socket is re-usable */
    optval = 1;
    result = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval));
    if (result < 0) {
        AFLOG_DEBUG1("conn_prv_ping:: setopt SO_RESUSEADDR failed");
		close(sockfd);
        return (0);
    }

    /* if no reply come back within 2 second, timeout */
    {
        struct timeval timeout;
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;
        result = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (result < 0) {
            AFLOG_DEBUG1("conn_prv_ping:: setopt SO_RCVTIMEO failed");
            close(sockfd);
            return (0);
        }
    }

    /** send the icmp request */
    result = sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&from, sizeof(struct sockaddr));
    AFLOG_DEBUG1("conn_prv_ping:: Sent %d byte packet to %s (from %s) on itf:%s, ip->check=%d, result =%d",
                 ip->tot_len, dst_addr_p, src_addr_p, itf_string, ip->check, result);

    /* trying to receive an icmp reply */
    memset(buffer, 0, sizeof(buffer));
    addrlen = sizeof(from);
    result = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &from, &addrlen);
    AFLOG_DEBUG2("conn_prv_ping:: recvfrom: result =%d", result);
    while ((result == -1) && (errno == EAGAIN) && (counter < 3)) {
        // Let's give another try to read
        result = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &from, &addrlen);
        if (result > 0) {
            break;
        }
        counter ++;
    }


    /* Close the socket & return the result */
    close(sockfd);
    if (result < 0) {
        AFLOG_ERR("conn_prv_ping:: Ping receive error, errno=%d (%s), counter=%d",
                  errno, strerror(errno), counter);
        return (-1);
    }
    else {
        AFLOG_DEBUG2("conn_prv_ping:: Receive OK, tried to recv: %d", counter);
        return (1);
    }
}


/*
 * send an echo to echo service (echo.dev.afero.io), and wait
 * for an response back.  The service lives behind the load balancer,
 * we need to resolve its address first before we can send a packet.
 *
 * if it gets a response back, the assume the service (i.e conclave
 * is alive).
 *
 * [IN]
 * host: the service name
 *
 * Return:
 * 1: successful
 * 0 or less : failed
 */
int8_t cm_echo_alive_check (const char   *host,  char *itf_string) {
    struct addrinfo hints, *res = NULL, *ai = NULL;
    int             errcode;
    void            *ptr;
    int             fd = -1;
    uint8_t         packet = 0x49;   // 1 byte packet, with value I
    uint8_t         buffer[10];
    char            s[INET6_ADDRSTRLEN];
    int             result = -1;
    struct sockaddr_in  *sock_addr_ptr;
    struct sockaddr_in6  *sock_addr6_ptr;
	int flags;


    if ((host == NULL) || (itf_string == NULL)) {
        AFLOG_ERR("cm_echo_alive_check:: Invalid input, host=%p, itf_string=%p", host, itf_string);
        return (-1);
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags |= AI_CANONNAME;
    hints.ai_flags = 0;
    errcode = getaddrinfo(host, NULL, &hints, &res);
    if (errcode != 0) {
        AFLOG_ERR("cm_echo_alive_check::getaddrinfo for host=%s - failed, err=%d", host, errcode);
        return (-1);
    }

    /* Loop through the IPv4 address returned, until one is connected */
    AFLOG_DEBUG3("cm_echo_alive_check:: Looping through the addresses ..... ");
    for (ai = res; ai; ai = ai->ai_next) {
        AFLOG_DEBUG2("  itf:%s:  ai->ai_family=%d, ai->socktype=%d, ai->ai_protocol=%d",
					itf_string,
                   ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            AFLOG_ERR("cm_echo_alive_check:: %s, socket failed %d:%s", itf_string, errno, strerror(errno));
            continue;  // try next address
        }

		/* default assume it is for IPv */
        sock_addr_ptr = (struct sockaddr_in *) ai->ai_addr;
        sock_addr_ptr->sin_port = htons(ECHO_SERVICE_PORT);
        if (ai->ai_addr->sa_family == AF_INET6) {
            sock_addr6_ptr = (struct sockaddr_in6 *) ai->ai_addr;
            sock_addr6_ptr->sin6_port = htons(ECHO_SERVICE_PORT);
        }
        /* using an specific interface */
        if (itf_string != NULL) {
            result = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, itf_string, IFNAMSIZ - 1);
            if (result < 0) {
                AFLOG_ERR("cm_echo_alive_check:: %s-(%s), setopt SO_BINDTODEVICE failed %d:%s",
                          itf_string, s, errno, strerror(errno));
                goto done;
            }
        }

		AFLOG_DEBUG2("cm_echo_alive_check::Connect() -- attempt to connect");

		// make connect call non-blocking
		flags = fcntl(fd, F_GETFL, 0);
		flags |= O_NONBLOCK; 
		fcntl(fd, F_SETFL, flags);
		if ((result = connect(fd, ai->ai_addr, ai->ai_addrlen)) == 0) { // connected
			flags = fcntl(fd, F_GETFL, 0);
			flags &= (~O_NONBLOCK);
			fcntl(fd, F_SETFL, flags);
			break;
        } else {  //
			if ((result == -1) && (errno != EINPROGRESS)) {
				inet_ntop(ai->ai_family, AF_INET == ai->ai_addr->sa_family ?
						(void *) (&(((struct sockaddr_in *) ai->ai_addr)->sin_addr)) :
						(void *) (&(((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr)), s, sizeof(s));
				AFLOG_DEBUG2("cm_echo_alive_check::dev=%s, connect() failed to (%s) for socket %d",
							itf_string, s, fd);
				close(fd);
				fd = -1;
			}
			else {
				struct timeval ctimeout;
				fd_set write_fd;

				FD_ZERO(&write_fd);
				FD_SET(fd, &write_fd);
				ctimeout.tv_sec  = 2;
				ctimeout.tv_usec = 0;

				// check if the socket is ready after the specified time
				result = select(fd+1, NULL, &write_fd, NULL, &ctimeout);
				if (result > 0) {
					AFLOG_DEBUG1("cm_echo_alive_check::dev=%s, ready to write, result=%d", itf_string, result);
					flags = fcntl(fd, F_GETFL, 0);
					flags &= (~O_NONBLOCK);
					fcntl(fd, F_SETFL, flags);
					break;
				}
				else {
					inet_ntop(ai->ai_family, AF_INET == ai->ai_addr->sa_family ?
							(void *) (&(((struct sockaddr_in *) ai->ai_addr)->sin_addr)) :
							(void *) (&(((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr)), s, sizeof(s));
					AFLOG_DEBUG1("cm_echo_alive_check::dev=%s, connect() TO (%s) for socket %d TIMEOUT",
								itf_string, s, fd);
					close(fd);
					fd = -1;
				}
			}
        }
    }

    AFLOG_DEBUG2("cm_echo_alive_check:: dev=%s, fd=%d", itf_string, fd);
    // we will try to send a 1 byte packet to echo service
    if ((ai != NULL) && (fd != -1)) {  // good to go
        int optval;

        /* get the IP address of the socket that we are open to */
        memset(s, 0, sizeof(s));
        ptr = &((struct sockaddr_in *) ai->ai_addr)->sin_addr;  // default to IPv4
        if (ai->ai_family == AF_INET6) {
            ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
        }
        inet_ntop(res->ai_family, ptr, s, sizeof(s));
        AFLOG_DEBUG2("cm_echo_alive_check::Connect(): to address %s for socket %d", s, fd);

        /* make this socket reusable */
        optval = 1;
        result = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(optval));
        if (result < 0) {
            AFLOG_ERR("cm_echo_alive_check:: %s-%s setopt SO_RESUSEADDR failed, err=%d:%s",
                         itf_string, s, errno, strerror(errno));
            goto done;
        }

        /* if no reply come back within the specified second, timeout */
        {
            struct timeval timeout;
            timeout.tv_sec  = 2;      // 2 seconds
            timeout.tv_usec = 0;
            result = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            if (result < 0) {
                AFLOG_DEBUG2("cm_echo_alive_check:: %s-%s setopt SO_RCVTIMEO failed ", itf_string, s);
                goto done;
            }
        }

        /** send the echo request with 1 byte of data */
        result = send(fd, (void *) &packet, 1, 0);
        AFLOG_DEBUG1("cm_echo_alive_check:: sent: 1 byte packet (val=%0X) to %s from %s, result=%d",
                     packet, s, itf_string, result);
        if (result < 0) {
            goto done;
        }

        /* trying to receive an echo reply */
        memset(buffer, 0, sizeof(buffer));
        result = recv(fd, buffer, sizeof(buffer), 0);
        if (result != 1) {   // should be 1 byte
            AFLOG_DEBUG1("cm_echo_alive_check:: recv: len=%d, echo val=%0X", result, buffer[0]);
            AFLOG_DEBUG1("cm_echo_alive_check:: recv: err=%d, %s", errno,strerror(errno));
            result = 0;
        }
    }

    done:
        if (fd >= 0) {
            close(fd);
		}

		if (res) {
			freeaddrinfo(res);
		}

        AFLOG_INFO("cm_echo_alive_check:: on interface (%s): echo %s from server (%s)",
				   itf_string,
                   ((result == 1) ? "ALIVE" : "FAILED"), s);

        return (result);
}


/* API to check if the service is alive,
 * using either ping or send an echo to the echo service.
 *
 * use_echo: 1 => send a 1 byte to the echo afero service
 *           0 => ping the known server
 */
int8_t
cm_is_service_alive(const char *service,    // service name (echo) or IP addr (ping)
                    const char *itf_string, // interface name
                    uint8_t    use_echo)    // using echo method?
{
    if (use_echo) {  // supported by the 'echo' server
        return cm_echo_alive_check(service, (char *)itf_string);
    }
    else {
        return conn_prv_ping(service, PING_ADDR, itf_string);
    }
}
