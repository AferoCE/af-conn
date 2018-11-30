// created by vipul on 07/07/15
//
// Copyright (c) 2015 Afero, Inc. All rights reserved.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>

#include "af_log.h"

#ifdef BUILD_TARGET_DEBUG
uint32_t g_debugLevel = 3;
#else
uint32_t g_debugLevel = 1;
#endif

#define BUF_SIZE 1024
#define DEFAULT_WAIT_PERIOD 15
#define DEFAULT_DEVICE      "/dev/ttyACM0";

static const char sOkString[] = "OK";
static const char sCmeErrorString[] = "+CME ERROR";
static const char sErrorString[] = "ERROR";

/* returns -1 if error, 0 if OK, 1 if unknown */
static int check_response(char *buf, int len, int printRes)
{
    af_log_buffer(LOG_DEBUG3, "check", buf, len);

    // Get rid of trailing carriage return
    if (len && buf[len - 1] == '\r') {
        buf[len - 1] = '\0';
        len--;
    }

    // if empty response ignore
    if (len == 0) {
        return 1;
    }

    if (!strncmp(buf, sOkString, sizeof(sOkString)-1)) {
        return 0;
    } else if (!strncmp(buf, sCmeErrorString, sizeof(sCmeErrorString)-1) || !strncmp(buf, sErrorString, sizeof(sErrorString)-1)) {
        if (printRes) printf("%s\n", buf);
        return -1;
    } else {
        if (printRes) printf("%s\n", buf);
        return 1;
    }
}

static int write_device(int fd, char *buf)
{
    if (write(fd, buf, strlen(buf)) < 0) {
        AFLOG_ERR("atcmd:write:errno=%d:write to device", errno);
        return -1;
    }
    return 0;
}

static speed_t num_to_baud(int baud_num)
{
    speed_t retVal = B0;
    switch(baud_num) {
        case 50 : retVal = B50; break;
        case 75 : retVal = B75; break;
        case 110 : retVal = B110; break;
        case 134 : retVal = B134; break;
        case 150 : retVal = B150; break;
        case 200 : retVal = B200; break;
        case 300 : retVal = B300; break;
        case 600 : retVal = B600; break;
        case 1200 : retVal = B1200; break;
        case 1800 : retVal = B1800; break;
        case 2400 : retVal = B2400; break;
        case 4800 : retVal = B4800; break;
        case 9600 : retVal = B9600; break;
        case 19200 : retVal = B19200; break;
        case 38400 : retVal = B38400; break;
        case 57600 : retVal = B57600; break;
        case 115200 : retVal = B115200; break;
        case 230400 : retVal = B230400; break;
        case 460800 : retVal = B460800; break;
        case 921600 : retVal = B921600; break;
        default : break;
    }
    return retVal;
}

/* return -2 if timeout or -1 if other error */
static int read_device(int fd, char *buf, int wait_period_ms, int printRes)
{
    fd_set rfds;
    struct timeval tv;
    int result;
    int start = 0, end = 0;

    tv.tv_sec = wait_period_ms / 1000;
    tv.tv_usec = 1000 * (wait_period_ms - tv.tv_sec * 1000);

    while(1)
    {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        result = select(fd+1, &rfds, NULL, NULL, &tv);
        if (result < 0) {
            AFLOG_ERR("select:errno=%d:select failure", errno);
            return -1;
        } else if (result == 0) {
            /* timed out */
            return -2;
        } else if (FD_ISSET(fd, &rfds)) {
            int rc = read(fd, buf + end, BUF_SIZE - end);
            if (rc < 0) {
                AFLOG_ERR("read:errno=%d:unable to read", errno);
                return -1;
            } else if (rc == 0) {
                AFLOG_WARNING("offline::tty port was closed");
                return -1;
            }

            /* check for overrun */
            end += rc;
            if (end > BUF_SIZE) {
                AFLOG_ERR("overrun:end=%d:buffer overrun", end);
                return -1;
            }

            // Check for lines
            for (int i = start; i < end; i++) {
                if (buf[i] == '\n') {
                    buf[i] = '\0';
                    int result = check_response(buf + start, i - start, printRes);
                    if (result <= 0) {
                        return result;
                    }
                    start = i+1;
                }
            }
        }
    }
}

void usage(char *argv0)
{
    fprintf(stderr, "usage: %s [ -b <baud_rate> ] [-d <device>] [-w <wait_period>] <command>\n", argv0);
}

int main(int argc, char *argv[])
{
    int fd;
    struct termios ios;
    char buf[BUF_SIZE];
    int wait_period = DEFAULT_WAIT_PERIOD;
    char *device = DEFAULT_DEVICE;
    char *cmd;
    int ret = -1;
    int opt;
    speed_t baud = B115200;

    openlog("atcmd", LOG_PID, LOG_USER);

    while ((opt = getopt(argc, argv,"b:d:w:")) != -1) {
        switch (opt) {
            case 'd' :
                device = optarg;
                break;
            case 'w' :
                wait_period = atoi(optarg);
                break;
            case 'b' :
                baud = num_to_baud(atoi(optarg));
                if (baud == B0) {
                    fprintf(stderr, "unknown baud rate: %s\n", optarg);
                    AFLOG_ERR("unknown baud rate: %s", optarg);
                    exit(1);
                }
                break;
            default :
                usage(argv[0]);
                goto close_log;
                break;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        goto close_log;
    }

    cmd = argv[optind];

    //opening and setting attributes for ttyACM0
    fd = open(device, O_RDWR | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) {
        AFLOG_ERR("open:errno=%d:unable to open tty device", errno);
        goto close_log;
    }

    tcgetattr(fd, &ios);
    cfsetispeed(&ios, baud);
    cfsetospeed(&ios, baud);

    ios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                     | INLCR | IGNCR | ICRNL | IXON);
    ios.c_oflag &= ~OPOST;
    ios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    ios.c_cflag &= ~(CSIZE | PARENB);
    ios.c_cflag |= CS8;

    tcsetattr(fd, TCSANOW, &ios);

    /* clean out any remaining data */
    if (read_device(fd, buf, 200, 0) == -1) {
        goto close_fd;
    }

    if (write_device(fd, "ate0\r") < 0) {
        goto close_fd;
    }

    ret = read_device(fd, buf, 2000, 0);
    if (ret < 0) {
        if (ret == -2) {
            AFLOG_WARNING("timeout on ate0 after 2000 ms");
        }
        goto close_fd;
    }

    // write to the device
    if (write_device(fd, cmd) < 0) {
        goto close_fd;
    }

    if (write_device(fd, "\r") < 0) {
        goto close_fd;
    }

    // read the device
    ret = read_device(fd, buf, wait_period * 1000, 1);
    if (ret == -2) {
        AFLOG_WARNING("timeout:wait_period=%d:read timed out", wait_period);
    }

close_fd:
    close(fd);

close_log:
    closelog();
    return ret;
}
