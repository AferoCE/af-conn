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

static int read_device(int fd, char *buf, int wait_period, int printRes)
{
    fd_set rfds;
    struct timeval tv;
    int result;
    int bufPos = 0;

    tv.tv_sec = wait_period;
    tv.tv_usec = 0;

    while(1)
    {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        result = select(fd+1, &rfds, NULL, NULL, &tv);
        if (result < 0) {
            AFLOG_ERR("select:errno=%d:select failure", errno);
            return -1;
        } else if (result == 0) {
            AFLOG_WARNING("timeout:wait_period=%d:read timed out", wait_period);
            write_device(fd, "^c");
            return -1;
        } else if (FD_ISSET(fd, &rfds)) {
            int rc = read(fd, buf + bufPos, BUF_SIZE - bufPos);
            if (rc < 0) {
                AFLOG_ERR("read:errno=%d:unable to read", errno);
                return -1;
            } else if (rc == 0) {
                AFLOG_WARNING("offline::tty port was closed");
                return -1;
            }

            /* check for overrun */
            bufPos += rc;
            if (bufPos > BUF_SIZE) {
                AFLOG_ERR("overrun:buf_pos=%d:buffer overrun", bufPos);
                return -1;
            }
            buf[bufPos] = '\0';

            // Check for lines
            int i, lastPos = 0;
            for (i = 0; i < bufPos; i++) {
                if (buf[i] == '\n') {
                    buf[i] = '\0'; // replace the newline with a terimator
                    int result = check_response(buf + lastPos, i - lastPos, printRes);
                    if (result <= 0) {
                        return result;
                    }
                    lastPos = i+1;
                }
            }
            if (lastPos < bufPos) {
                for (i = 0; i < bufPos - lastPos; i++) {
                     buf[i] = buf[lastPos + i];
                }
            }
        }
    }
}

void usage(char *argv0)
{
    fprintf(stderr, "usage: %s [-d <device>] [-w <wait_period>] <command>\n", argv0);
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

    openlog("atcmd", LOG_PID, LOG_USER);

    while ((opt = getopt(argc, argv,"d:w:")) != -1) {
        switch (opt) {
            case 'd' :
                device = optarg;
                break;
            case 'w' :
                wait_period = atoi(optarg);
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
    if (cfsetispeed(&ios, B230400) < 0) {
        AFLOG_ERR("baud:errno=%d:failed to change input baud rate", errno);
        goto close_fd;
    }
    ios.c_lflag = 0;
    tcsetattr(fd, TCSANOW, &ios);

    if (write_device(fd, "ate0\r\n") < 0) {
        goto close_fd;
    }

    if (read_device(fd, buf, 1, 0) < 0) {
        goto close_fd;
    }

    // write to the device
    if (write_device(fd, cmd) < 0) {
        goto close_fd;
    }

	if (write_device(fd, "\r\n") < 0) {
        goto close_fd;
    }

    // read the device
    ret = read_device(fd, buf, wait_period, 1);

close_fd:
    close(fd);

close_log:
    closelog();
    return ret;
}
