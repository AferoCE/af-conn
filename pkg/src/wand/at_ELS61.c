/*
 * at.c -- AT command handler definitions
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Kai Hu, Evan Jeng, and Clif Liu
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <event2/event.h>

#include "at.h"
#include "af_log.h"

static char sBuf[2048];
static struct event *sIoEvent = NULL;
static int sAtFd = -1;

#define AT_REQ_BUF_SIZE 256
#define AT_RSP_BUF_SIZE 1024
#define AT_RSP_MAX_LINES 15
#define AT_TIMEOUT_SECONDS 10

static pthread_mutex_t sAtMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sAtCond; // Initialized manually to use CLOCK_MONOTONIC
static pthread_condattr_t sAtCondAttr;
static uint8_t sAtCondCreated = 0;
static uint8_t sAtCondAttrCreated = 0;
static at_result_t sAtResult;
static at_response_type_t sAtRspType;
static char *sAtPrefix;
static char sAtRspBuf[AT_RSP_BUF_SIZE];
static char *sAtRspLines[AT_RSP_MAX_LINES];
static int sAtRspNumLines;
static int sAtRspBufPos;
static int sAtRspCurrentLine;
static int sAtChannelUp = 0;
static int sAtError;

#define AT_MAX_UNSOL_DEFS 10
static char *sUnsolPrefixTable[AT_MAX_UNSOL_DEFS];
static at_unsol_callback_t sUnsolCallback[AT_MAX_UNSOL_DEFS];
static void *sUnsolContext = NULL;
static int sUnsolCount = 0;

static void prv_on_at_receive(char *buf, int len);

/**************************************************************************************************/
/* AT Command Channel Management
*/
static void log_buf(char *buf)
{
    char outBuf[2048];
    char *buf2 = outBuf;
    int len = 0;
    while (*buf) {
        if (*buf == '\n') {
            *buf2++ = '\\';
            *buf2++ = 'n';
        } else if (*buf != '\r') {
            *buf2++ = *buf;
        }
        buf++;
        len++;
    }
    *buf2='\0';
    AFLOG_DEBUG3("prv_at_recv_cb::received %d bytes {%s}", len, outBuf);
}

static void prv_on_io_event(evutil_socket_t fd, short what, void *arg)
{
    int len;

    len = read(sAtFd, sBuf, sizeof(sBuf) - 1);
    if (len <= 0) {
        AFLOG_ERR("prv_on_at_io:read_fail:errno=%d", errno);
        prv_on_at_receive(NULL, len);
        return;
    }
    sBuf[len] = '\0';

    if (g_debugLevel >= LOG_DEBUG3) {
        log_buf(sBuf);
    }


    /* reschedule event only if read is successful */
    event_add(sIoEvent, NULL);

    prv_on_at_receive(sBuf, len);
}

void at_shutdown(void)
{
    if (sAtChannelUp) {
        if (sIoEvent) {
            event_del(sIoEvent);
            event_free(sIoEvent);
            sIoEvent = NULL;
        }

        if (sAtFd >= 0) {
            close(sAtFd);
            sAtFd = -1;
        }
        sAtChannelUp = 0;
    }

    if (sAtCondCreated) {
        pthread_cond_destroy(&sAtCond);
        sAtCondCreated = 0;
    }

    if (sAtCondAttrCreated) {
        pthread_condattr_destroy(&sAtCondAttr);
        sAtCondAttrCreated = 0;
    }
}

int at_init(char *device, struct event_base *base, at_unsol_def_t *defs, int numDefs, void *context)
{
    struct termios ios;
    int err;

    if (device == NULL || base == NULL || defs == NULL || numDefs < 0 || numDefs > AT_MAX_UNSOL_DEFS) {
        AFLOG_ERR("at_init_params:device_NULL=%d,base_NULL=%d,defs_NULL=%d,numDefs=%d",
                  device==NULL, base==NULL, defs==NULL, numDefs);
        errno = EINVAL;
        return -1;
    }
    sAtChannelUp = 0;

    /* set up unsolicited event structures */
    sUnsolContext = context;
    int i;
    for (i = 0; i < numDefs; i++) {
        sUnsolPrefixTable[i] = defs[i].prefix;
        sUnsolCallback[i] = defs[i].callback;
    }
    sUnsolCount = numDefs;

    if (pthread_condattr_init(&sAtCondAttr) < 0) {
        AFLOG_ERR("ril_init:pthread_condattr_init:errno=%d", errno);
        goto error;
    }
    sAtCondAttrCreated = 1;

    pthread_condattr_setclock(&sAtCondAttr, CLOCK_MONOTONIC);

    if (pthread_cond_init(&sAtCond, &sAtCondAttr) < 0) {
        AFLOG_ERR("ril_init:pthread_cond_init:errno=%d", errno);
        goto error;
    };
    sAtCondCreated = 1;

    sAtFd = open(device, O_RDWR | O_NONBLOCK | O_NOCTTY );
    if (sAtFd < 0) {
        AFLOG_ERR("at_init_open:errno=%d:unable to open device", errno);
        goto error;
    }

    tcgetattr(sAtFd, &ios);

    if (cfsetispeed(&ios, B230400) < 0) {
        AFLOG_ERR("at_init_input_baud:errno=%d:failed to change input baud rate", errno);
        goto error;
    }

    if (cfsetospeed(&ios, B230400) < 0) {
        AFLOG_ERR("at_init_output_baud:errno=%d:failed to change output baud rate", errno);
        goto error;
    }

    ios.c_lflag = 0;
    tcsetattr(sAtFd, TCSANOW, &ios);
    
    sIoEvent = event_new(base, sAtFd, EV_READ, prv_on_io_event, NULL);
    if (sIoEvent == NULL) {
        AFLOG_ERR("at_init:create_event:errno=%d:unable to create IO event", errno);
        goto error;
    }

    event_add(sIoEvent, NULL);
    sAtChannelUp = 1;

    return 0;

error:

    err = errno;
    at_shutdown();
    errno = err;

    return -1;
}

static void prv_modem_down(void)
{
    at_shutdown();
    sAtChannelUp = 0;
}

/**************************************************************************************************/
/* Functions to send AT commands
*/

void at_start_cmds(void)
{
    pthread_mutex_lock(&sAtMutex);
}

void at_end_cmds(void)
{
    pthread_mutex_unlock(&sAtMutex);
}

static void prv_rspbuf_clear(void);

#define NUM_AT_SEND_TRIES 1

at_result_t at_send_cmd(at_response_type_t rspType, char *prefix, char *opt, int timeout)
{
    struct timespec ts;
    char buf[AT_REQ_BUF_SIZE];

    if (!sAtChannelUp) {
        sAtResult = AT_RESULT_SEND_FAILED;
        AFLOG_ERR("at_send_cmd:not_up::");
        goto exit;
    }

    if (opt == NULL)
        opt = "";

    sAtResult = AT_RESULT_SUCCESS;

    /* generate AT command */
    int len = snprintf(buf, sizeof(buf), "AT%s%s\r\n", prefix, opt);
    if (len >= sizeof(buf))
    {
        AFLOG_ERR("ril_at_cmd_async::failed to generate at command");
        goto exit;
    }

    /* send AT command and wait for response */
    AFLOG_DEBUG3("Sending: %s", buf);

    sAtRspType = rspType;
    sAtPrefix = prefix;

    prv_rspbuf_clear();

    int tries = 0;
    while (tries++ < NUM_AT_SEND_TRIES) {
        sAtResult = AT_RESULT_PENDING;

        if (sAtFd >= 0) {
            int bytes = write(sAtFd, buf, len);
            if (bytes != len) {
                /* failed to write the requested number of bytes */
                AFLOG_ERR("at_send:write_failure:wrote=%d,requested=%d,errno=%d", bytes, len, errno);
                prv_modem_down();
                sAtResult = AT_RESULT_SEND_FAILED;
                goto exit;
            }
        } else {
            prv_modem_down();
            sAtResult = AT_RESULT_SEND_FAILED;
            goto exit;
        }

        clock_gettime(CLOCK_MONOTONIC, &ts);
        int to = (timeout > 0 ? timeout : AT_TIMEOUT_SECONDS);
        ts.tv_sec += to;
        while (sAtResult == AT_RESULT_PENDING) {
            if (pthread_cond_timedwait(&sAtCond, &sAtMutex, &ts) != ETIMEDOUT) {
                goto exit;
            }
            AFLOG_WARNING("at_send_cmd_timeout:timeout=%d,try=%d,maxTries=%d", to, tries, NUM_AT_SEND_TRIES);
            sAtResult = AT_RESULT_TIMEDOUT;
        }
    }

    if (sAtResult == AT_RESULT_TIMEDOUT) {
        AFLOG_ERR("at_send_cmd_timeout_locked::modem not responding to AT commands; power cycling...");
        prv_modem_down();
    }

exit:
    sAtRspType = AT_RSP_TYPE_INVALID;

    return sAtResult;
}

at_result_t at_send_query(at_response_type_t type, char *prefix, int timeout)
{
    char *opt = "?";
    return at_send_cmd(type, prefix, opt, timeout);
}

at_result_t at_send_cmd_1_int(at_response_type_t type, char *prefix, int arg, int timeout)
{
    char opt[16];
    if (snprintf(opt, sizeof(opt), "=%d", arg) >= sizeof(opt)) {
        return -1;
    }
    return at_send_cmd(type, prefix, opt, timeout);
}

at_result_t at_send_cmd_2_int(at_response_type_t type, char *prefix, int arg1, int arg2, int timeout)
{
    char opt[16];
    if (snprintf(opt, sizeof(opt), "=%d,%d", arg1, arg2) >= sizeof(opt)) {
        return -1;
    }
    return at_send_cmd(type, prefix, opt, timeout);
}


/**************************************************************************************************/
/* Functions to handle raw AT output
*/

#define ERROR_PREFIX "ERROR"
#define CME_ERROR_PREFIX "+CME ERROR:"
#define CMS_ERROR_PREFIX "+CMS ERROR:"

static int prv_prefix_table_find(char *str, char **tbl, size_t size)
{
    int i;
    char *prefix;
    for (i = 0; i < size; i++) {
        prefix = tbl[i];
        if (strncmp(str, prefix, strlen(prefix)) == 0) {
            return i;
        }
    }
    return -1;
}

static void prv_handle_unsol(char *line)
{
    int event = prv_prefix_table_find(line, sUnsolPrefixTable, sUnsolCount);
    if (event >= 0) {
        /* skip over event name */
        while (*line != ':') {
            line++;
        }
        line++;

        if (sUnsolCallback[event]) {
            (sUnsolCallback[event])(line, sUnsolContext);
        }
    }
}

static void prv_rspbuf_clear(void)
{
    sAtRspBufPos = 0;
    sAtRspCurrentLine = 0;
    sAtRspNumLines = 0;
}

static int prv_rspbuf_add(char *line)
{
    if (sAtRspNumLines >= AT_RSP_MAX_LINES) {
        AFLOG_ERR("prv_handle_at_response:lines::too many AT response lines");
        return AT_RESULT_ERROR;
    }
    if (sAtRspBufPos < sizeof(sAtRspBuf) - 1) {
        sAtRspLines[sAtRspNumLines++] = &sAtRspBuf[sAtRspBufPos];
        sAtRspBufPos += snprintf (&sAtRspBuf[sAtRspBufPos], sizeof(sAtRspBuf) - sAtRspBufPos, "%s", line) + 1;
    }
    return AT_RESULT_SUCCESS;
}

/* this is called while the sAtMutex is locked */
static void prv_parse_at_input(char *buf)
{
    char *line, *nextline;
    at_result_t atResult = AT_RESULT_SUCCESS;
    int atError = 0;
    int cmdReceived = 0;


    line = buf;
    while (1) {
        /* remove leading CR/LF */
        while (*line == '\r' || *line == '\n') {
            line++;
        }

        /* check if we've hit the end of the buffer */
        if (*line == '\0') {
            break;
        }

        /* find the end of the line */
        char *cp = line;
        while (*cp != '\r' && *cp != '\n' && *cp != '\0') {
            cp++;
        }

        /* terminate the line if it ends with a carriage return */
        if (*cp == '\r' || *cp == '\n') {
            *cp++ = '\0';
        }
        nextline = cp;
        AFLOG_DEBUG3("prv_parse_at_input:line=%s", line);

        if (sAtRspType == AT_RSP_TYPE_INVALID) {
            /* not expecting a response to a command */
            prv_handle_unsol(line);
        } else {
            if (!strncmp(line, ERROR_PREFIX, sizeof(ERROR_PREFIX) - 1)) {
                atError = strtol(&line[sizeof(ERROR_PREFIX) - 1], NULL, 10);
                atResult = AT_RESULT_ERROR;
                cmdReceived = 1;
            } else if (!strncmp(line, CME_ERROR_PREFIX, sizeof(CME_ERROR_PREFIX) - 1)) {
                atError = strtol(&line[sizeof(CME_ERROR_PREFIX) - 1], NULL, 10);
                atResult = AT_RESULT_CME_ERROR;
                cmdReceived = 1;
            } else if (!strncmp(line, CMS_ERROR_PREFIX, sizeof(CMS_ERROR_PREFIX) - 1)) {
                atError = strtol(&line[sizeof(CMS_ERROR_PREFIX) - 1], NULL, 10);
                atResult = AT_RESULT_CMS_ERROR;
                cmdReceived = 1;
            } else if (sAtRspType == AT_RSP_TYPE_PREFIX) {
                if (strncmp(line, sAtPrefix, strlen(sAtPrefix)) == 0) {
                    /* skip to after ": " */
                    while (*line != ':') {
                        line++;
                    }
                    line++;
                    line++;

                    /* add line to list of lines */
                    atResult = prv_rspbuf_add(line);
                } else if (!strncmp(line, "OK", 2)) {
                    /* matches prefix of command */
                    cmdReceived = 1;
                } else {
                    /* does not match prefix of command */
                    prv_handle_unsol(line);
                }
            } else if (sAtRspType == AT_RSP_TYPE_NO_PREFIX) {
                if (prv_prefix_table_find(line, sUnsolPrefixTable, sUnsolCount) >= 0) {
                    prv_handle_unsol(line);
                } else if (!strncmp(line, "OK", 2)) {
                    cmdReceived = 1;
                } else {
                    atResult = prv_rspbuf_add(line);
                }
            } else { /* this is a AT_RSP_TYPE_OK */
                if (!strncmp(line, "OK", 2)) {
                    /* success */
                    cmdReceived = 1;
                } else {
                    prv_handle_unsol(line);
                }
            }
        }

        line = nextline;
    }

    if (cmdReceived) {
        sAtResult = atResult;
        sAtError = atError;
        pthread_cond_signal(&sAtCond);
    }
}

static void prv_on_at_receive(char *buf, int len)
{
    pthread_mutex_lock(&sAtMutex);

    if (sAtChannelUp == 0) {
        goto exit;
    }

    if (buf == NULL) {
        prv_modem_down();
        goto exit;
    }

    // Signals thread if response to a command
    prv_parse_at_input(buf);

exit:
    pthread_mutex_unlock(&sAtMutex);
}

/**************************************************************************************************/
/* tokenize function
*/

int at_tokenize_line(char *line, char tok, char **list, int len)
{
    if (line == NULL) {
        return -1;
    }

    char *p, **token;
    int count;

    token = list;
    p = line;
    count = 0;
    while (count < len) {
        /* find token start */
        while (*p == ' ' || *p == ',' || *p == '\"' || *p == '\0') {
            p++;
        }

        if (*p == '\0' || *p == '\r' || *p == '\n')
            break;

        *token++ = p;
        count++;
        /* find token end */
        while (*p != tok && *p != '\"' && *p != '\0' && *p != '\r' && *p != '\n') {
            p++;
        }

        if (*p == '\0')
            break;

        *p++ = '\0';
    }
    return count;
}

int at_rsp_num_lines(void)
{
    return sAtRspNumLines;
}

char *at_rsp_next_line(void)
{
    if (sAtRspCurrentLine < sAtRspNumLines) {
        return sAtRspLines[sAtRspCurrentLine++];
    } else {
        return NULL;
    }
}

int at_rsp_error(void)
{
    return sAtError;
}

