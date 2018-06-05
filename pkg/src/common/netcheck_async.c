/*
 * netcheck.c -- active check to see if network is up
 *
 * Copyright (c) 2016-2018, Afero Inc. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
//#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
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
#include <event2/event.h>
#include <pthread.h>
#include <af_log.h>
#include "../include/hub_config.h"
#include "../include/netcheck_async.h"

const char  *PING_ADDR = "8.8.8.8";


/*
 * in_cksum --
 * Checksum routine for Internet Protocol
 * family headers (C Version)
 * -- from the "open source"
 */
static unsigned short
in_cksum(unsigned short *addr, int len)
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


#define PING_TIMEOUT_SEC 1

/* Internal help function to send a ping request and get a reply */
static int
ping_check(const char *src_addr, const char *dst_addr, const char *itf_string)
{
    uint8_t packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
    uint8_t buffer[128];
    struct iphdr *ip;
    struct icmphdr *icmp;
    int sockfd = -1;
    struct sockaddr_in from;
    uint32_t addrlen;
    int result;
    int counter = 0;

    if ((src_addr == NULL) || (dst_addr == NULL)) {
        AFLOG_ERR("ping_check_param:src_addr_NULL=%d,dst_addr_NULL=%d",
                  src_addr == NULL, dst_addr == NULL);
        return -1;
    }

    memset(packet, 0, sizeof(packet));

    ip = (struct iphdr *) packet;
    icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

    /** setup the ip packet,  except checksum  */
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->id = htons(random());
    ip->ttl = 255;
    ip->protocol = IPPROTO_ICMP;
    ip->saddr = inet_addr(src_addr);
    ip->daddr = inet_addr(dst_addr);

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        AFLOG_ERR("ping_check:errno=%d:socket failed", errno);
        return -1;
    }

    /* tell the kernel to automatically tag on a IP header */
    int optval = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = random();
    icmp->un.echo.sequence = 0;
    icmp->checksum = 0;
    icmp->checksum = in_cksum((unsigned short *) icmp, sizeof(struct icmphdr));

    ip->check = in_cksum((unsigned short *) ip, sizeof(struct iphdr));

    from.sin_family = AF_INET;
    from.sin_addr.s_addr = inet_addr(dst_addr);

    /* using an specific interface */
    if (itf_string) {
        result = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, itf_string, IFNAMSIZ - 1);
        if (result < 0) {
            AFLOG_ERR("ping_check_bind_interface:errno=%d:setopt SO_BINDTODEVICE failed", errno);
            close(sockfd);
            return -1;
        }
    }

    /* tell the kernel that the socket is re-usable */
    optval = 1;
    result = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(optval));
    if (result < 0) {
        AFLOG_ERR("ping_check_set_reuseaddr:errno=%d:setopt SO_RESUSEADDR failed", errno);
        close(sockfd);
        return -1;
    }

    /* if no reply come back within 2 second, timeout */
    {
        struct timeval timeout = { PING_TIMEOUT_SEC, 0 };
        result = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (result < 0) {
            AFLOG_ERR("ping_check_set_timeout:errno=%d:setopt SO_RCVTIMEO failed", errno);
            close(sockfd);
            return -1;
        }
    }

    /** send the icmp request */
    result = sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&from, sizeof(struct sockaddr));
    if (itf_string) {
        AFLOG_DEBUG2("ping_check_sent:len=%d,dst_addr=%s,src_addr=%s,dev=%s,check=%d,result=%d",
                     ip->tot_len, dst_addr, src_addr, itf_string, ip->check, result);
    } else {
        AFLOG_DEBUG2("ping_check_sent:len=%d,dst_addr=%s,src_addr=%s,check=%d,result=%d",
                     ip->tot_len, dst_addr, src_addr, ip->check, result);
    }

    /* trying to receive an icmp reply */
    memset(buffer, 0, sizeof(buffer));
    addrlen = sizeof(from);
    result = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *) &from, &addrlen);
    AFLOG_DEBUG2("ping_check_recvfrom:result=%d", result);
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
        AFLOG_DEBUG1("ping_check_failed:errno=%d,counter=%d:ping receive error", errno, counter);
        return -1;
    }
    else {
        AFLOG_DEBUG1("ping_check_succeeded:tries=%d", counter);
        return 0;
    }
}


#define CONNECT_TIMEOUT_SEC 2
#define ECHO_TIMEOUT_SEC 2

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
static int
echo_check (const char *host, char *itf_string) {
    struct addrinfo hints, *res = NULL, *ai = NULL;
    int             errcode;
    int             fd = -1;
    uint8_t         buffer[10];
    char            addrstr[INET6_ADDRSTRLEN];
    int             result = -1;
    int             flags;

    AFLOG_DEBUG3("%s_enter", __func__);

    if ((host == NULL)) {
        AFLOG_ERR("echo_check_getaddrinfo:host_NULL=%d:", host);
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    AFLOG_DEBUG2("echo_check_getaddrinfo");
    errcode = getaddrinfo(host, NULL, &hints, &res);
    if (errcode != 0) {
        AFLOG_DEBUG1("echo_check_getaddrinfo:host=%s,errno=%d:getaddrinfo failed", host, errcode);
        return -1;
    }
    AFLOG_DEBUG2("echo_check_getaddrinfo_done:ai_NULL=%d", ai==NULL);

    // Loop through the addresses returned, until one is connected
    AFLOG_DEBUG2("echo_check_addr_loop::Looping through the addresses");
    for (ai = res; ai; ai = ai->ai_next) {

        // convert address to string; if it's not an IPv6 address assume it's an IPv4 address
        memset(addrstr, 0, sizeof(addrstr));
        if (ai->ai_addr->sa_family == AF_INET6) {
            ((struct sockaddr_in6 *)(ai->ai_addr))->sin6_port = htons(ECHO_SERVICE_PORT);
            inet_ntop(ai->ai_family, (void *) (&(((struct sockaddr_in6 *) ai->ai_addr)->sin6_addr)), addrstr, sizeof(addrstr));
        } else {
            ((struct sockaddr_in *)(ai->ai_addr))->sin_port = htons(ECHO_SERVICE_PORT);
            inet_ntop(ai->ai_family, (void *) (&(((struct sockaddr_in *) ai->ai_addr)->sin_addr)), addrstr, sizeof(addrstr));
        }

        AFLOG_DEBUG2("echo_check_address:family=%d,socktype=%d,ai_protocol=%d,addr=%s",
                     ai->ai_family, ai->ai_socktype, ai->ai_protocol, addrstr);

        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            AFLOG_ERR("echo_check_socket:addr=%s,errno=%d", addrstr, errno);
            continue;  // try next address
        }

        // force the socket to use a specific interface, if desired
        if (itf_string) {
            result = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, itf_string, IFNAMSIZ - 1);
            if (result < 0) {
                AFLOG_ERR("echo_check_bind_itf:itf=%s,errno=%d:setopt SO_BINDTODEVICE failed",
                          itf_string, errno);
                goto done;
            }
        }

        AFLOG_DEBUG2("echo_check_connect::attempt to connect");

        // make connect call non-blocking to allow us to control the timeout
        flags = fcntl(fd, F_GETFL, 0);
        flags |= O_NONBLOCK;
        fcntl(fd, F_SETFL, flags);

        if ((result = connect(fd, ai->ai_addr, ai->ai_addrlen)) == 0) { // connected
            break;
        } else {  //
            if ((result == -1) && (errno != EINPROGRESS)) {
                if (itf_string) {
                    AFLOG_DEBUG1("echo_check_connect_failed1:dev=%s,addr=%s,fd=%d,errno=%d", itf_string, addrstr, fd, errno);
                } else {
                    AFLOG_DEBUG1("echo_check_connect_failed1:addr=%s,fd=%d,errno=%d", addrstr, fd, errno);
                }
                close(fd);
                fd = -1;
            }
            else {
                struct timeval ctimeout = { CONNECT_TIMEOUT_SEC, 0 };
                fd_set write_fd;
                FD_ZERO(&write_fd);
                FD_SET(fd, &write_fd);

                // check if the socket is ready after the specified time
                result = select(fd+1, NULL, &write_fd, NULL, &ctimeout);
                if (result > 0) {
                    break;
                } else if (result == 0) {
                    if (itf_string) {
                        AFLOG_DEBUG1("echo_check_connect_timeout:dev=%s,addr=%s,fd=%d", itf_string, addrstr, fd);
                    } else {
                        AFLOG_DEBUG1("echo_check_connect_timeout:addr=%s,fd=%d", addrstr, fd);
                    }
                    close(fd);
                    fd = -1;
                } else {
                    if (itf_string) {
                        AFLOG_DEBUG1("echo_check_connect_failed2:dev=%s,addr=%s,errno=%d", itf_string, addrstr, errno);
                    } else {
                        AFLOG_DEBUG1("echo_check_connect_failed2:addr=%s,errno=%d", addrstr, errno);
                    }
                }
            }
        }
    }

    // we will try to send a 1 byte packet to echo service
    if ((ai != NULL) && (fd != -1)) {  // good to go
        if (itf_string) {
            AFLOG_DEBUG2("echo_check_connected:dev=%s,addr=%s", itf_string, addrstr);
        } else {
            AFLOG_DEBUG2("echo_check_connected:addr=%s", addrstr);
        }

        // set the socket blocking again so we can use a blocking recv with timeout
        flags = fcntl(fd, F_GETFL, 0);
        flags &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, flags);

        // make this socket reusable
        int optval = 1;
        result = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(optval));
        if (result < 0) {
            if (itf_string) {
                AFLOG_ERR("echo_check_reuseaddr:dev=%s,addr=%s,errno=%d:setopt SO_REUSEADDR failed",
                          itf_string, addrstr, errno);
            } else {
                AFLOG_ERR("echo_check_reuseaddr:addr=%s,errno=%d:setopt SO_REUSEADDR failed",
                          addrstr, errno);
            }
            goto done;
        }

        struct timeval timeout = { ECHO_TIMEOUT_SEC, 0 };
        result = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        if (result < 0) {
            if (itf_string) {
                AFLOG_ERR("echo_check_rcvtimeo:dev=%s,addr=%s,errno=%d:setopt SO_RCVTIMEO failed",
                          itf_string, addrstr, errno);
            } else {
                AFLOG_ERR("echo_check_rcvtimeo:addr=%s,errno=%d:setopt SO_RCVTIMEO failed",
                          addrstr, errno);
            }
            goto done;
        }

        // send the echo request with 1 byte of data
        char packet = 'I';
        if (itf_string) {
            AFLOG_DEBUG2("cmd_echo_alive_sending:dev=%s,addr=%s,val=0x%02x", itf_string, addrstr, packet);
        } else {
            AFLOG_DEBUG2("cmd_echo_alive_sending:addr=%s,val=0x%02x", addrstr, packet);
        }

        result = send(fd, (void *)&packet, 1, 0);
        if (result < 0) {
            AFLOG_INFO("echo_check_send:echo_val=0x%02x,errno=%d:send failed", packet, errno);
            goto done;
        } else {
            AFLOG_DEBUG2("echo_check_sent::");
        }

        // try to receive an echo reply
        memset(buffer, 0, sizeof(buffer));
        result = recv(fd, buffer, sizeof(buffer), 0);
        if (result != 1) {   // should be 1 byte
            AFLOG_INFO("echo_check_recv:len=%d,echo_val=0x%02x,errno=%d:receive failed", result, buffer[0], errno);
            result = -1;
        } else {
            if (itf_string) {
                AFLOG_DEBUG1("echo_check_succeeded:dev=%s,addr=%s", itf_string, addrstr);
            } else {
                AFLOG_DEBUG1("echo_check_succeeded:addr=%s", addrstr);
            }
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

    return result;
}

typedef struct {
    int fds[2];
    int status;
    struct event *listen_event;
    netcheck_callback_t callback;
    void *callback_context;
    pthread_t thread;
    char *host;
    char *itf_string;
    netcheck_type_t check_type;
} netcheck_context_t;

static void destroy_context(netcheck_context_t *c)
{
    if (c) {
        if (c->fds[0]) {
            close(c->fds[0]);
        }
        if (c->fds[1]) {
            close(c->fds[1]);
        }
        if (c->listen_event) {
            event_del(c->listen_event);
            event_free(c->listen_event);
        }
        if (c->host) {
            free(c->host);
        }
        if (c->itf_string) {
            free(c->itf_string);
        }
        free(c);
    }
}

static void
on_result(evutil_socket_t fd, short what, void *arg)
{
    AFLOG_DEBUG2("on_result:arg_NULL=%d,what=%d", arg==NULL,what);

    netcheck_context_t *c = (netcheck_context_t *)arg;
    if (c) {
        if (what & EV_READ) {
            void *ret = NULL;
            pthread_join(c->thread, &ret);
            AFLOG_DEBUG2("on_result_ret:ret=%d", (int)ret);
            if (c->callback) {
                (c->callback)((int)ret, c->callback_context);
            }
            destroy_context(c);
        } else if (what & EV_TIMEOUT) {
            void *ret = NULL;
            pthread_cancel(c->thread);
            pthread_join(c->thread, &ret);
            if (c->callback) {
                (c->callback)(NETCHECK_ERROR_TIMED_OUT, c->callback_context);
            }
            destroy_context(c);
        } else {
            /* log */
        }
    }
}

static void *
netcheck_thread(void *arg)
{
    int ret = -1;
    netcheck_context_t *c = (netcheck_context_t *)arg;
    AFLOG_DEBUG3("netcheck_thread_start:c_NULL=%d", c==NULL);
    if (c) {
        int result;

        if (c->check_type == NETCHECK_USE_ECHO) {  // supported by the 'echo' server
            AFLOG_DEBUG2("netcheck_thread_echo");
            result = echo_check(c->host, c->itf_string);
        } else {
            AFLOG_DEBUG2("netcheck_thread_ping");
            result = ping_check(c->host, PING_ADDR, c->itf_string);
        }

        AFLOG_DEBUG2("netcheck_thread_finished:result=%d",result);
        if (result) {
            AFLOG_DEBUG2("netcheck_thread_failed:errno=%d", errno);
            ret = errno;
        } else {
            ret = 0;
        }

        /* jingle the socket to tell everyone we're done */
        uint8_t zero = 0;
        write(c->fds[1], &zero, sizeof(zero));
    }
    AFLOG_DEBUG3("%s_exit:ret=%d",__func__,ret);
    return (void *)ret;
}


/* API to check if the service is alive,
 * using either ping or send an echo to the echo service.
 *
 * use_echo: 1 => send a 1 byte to the echo afero service
 *           0 => ping the known server
 */
int check_network(struct event_base *base,
                  const char *host,              // service name (echo) or IP addr (ping)
                  const char *itf_string,        // interface name
                  netcheck_type_t check_type,    // use ping or echo?
                  netcheck_callback_t callback,  // callback to call with result
                  void *context,
                  int timeout_msec)
{
    netcheck_context_t *c = NULL;
    int ret = 0;
    AFLOG_DEBUG3("enter %s", __func__);

    if (!base || !host || !callback) {
        AFLOG_ERR("%s_param:base_NULL=%d,host_NULL=%d,callback_NULL=%d",__func__,base==NULL,host==NULL,callback==NULL);
        errno = EINVAL;
        return -1;
    }

    /* allocate space for the context, and initialize it with 0s */
    c = (netcheck_context_t *)calloc(1, sizeof(netcheck_context_t));
    if (!c) {
        AFLOG_ERR("%s_context_alloc",__func__);
        return -1;
    }

    c->callback = callback;
    c->callback_context = context;
    c->check_type = check_type;
    c->host = strdup(host);
    if (!c->host) {
        AFLOG_ERR("%s_context_host_alloc",__func__);
        destroy_context(c);
        return -1;
    }
    if (itf_string) {
        c->itf_string = strdup(itf_string);
        if (!c->itf_string) {
            AFLOG_ERR("%s_context_itf_string_alloc",__func__);
            destroy_context(c);
            return -1;
        }
    } else {
        /* set the interface string to an empty string */
        c->itf_string[0] = '\0';
    }

    /* create the socket pair */
    if (socketpair(AF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, c->fds) < 0) {
        AFLOG_ERR("netcheck_async_socketpair:errno=%d:failed to create socket pair", errno);
        destroy_context(c);
        return -1;
    }

    /* create the event listening for the result */
    c->listen_event = event_new(base, c->fds[0], EV_READ, on_result, c);
    if (c->listen_event == NULL) {
        AFLOG_ERR("netcheck_async_event:errno=%d:failed to create event", errno);
        destroy_context(c);
        return -1;
    }

    /* add the event */
    struct timeval tv;
    tv.tv_sec = timeout_msec / 1000;
    tv.tv_usec = (timeout_msec % 1000) * 1000;
    event_add(c->listen_event, &tv);

    AFLOG_DEBUG2("check_network_creating_thread\n");
    /* create the thread */
    ret = pthread_create(&c->thread, NULL, netcheck_thread, c);
    if (ret != 0) {
        AFLOG_ERR("%s_thread:ret=%d",__func__,ret);
        destroy_context(c);
        errno = ret;
        return -1;
    }

    return 0;
}
