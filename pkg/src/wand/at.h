/*
 * at.h -- AT command handler definitions
 *
 * Copyright (c) 2015-2017, Afero, Inc. All rights reserved.
 *
 * Kai Hu, Evan Jeng, and Clif Liu
 */

#ifndef __AT_H__
#define __AT_H__

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ((sizeof x) / (sizeof *x))
#endif

#include <event2/event.h>

typedef enum {
    AT_RESULT_SUCCESS = 0,
    AT_RESULT_ERROR,
    AT_RESULT_CME_ERROR,
    AT_RESULT_CMS_ERROR,
    AT_RESULT_TIMEDOUT,
    AT_RESULT_PENDING,
    AT_RESULT_SEND_FAILED,
    AT_RESULT_INVALID
} at_result_t;

typedef enum {
    AT_RSP_TYPE_OK = 0,    // "OK"
    AT_RSP_TYPE_PREFIX,    // 1+ lines beginning with prefix, followed by "OK"
    AT_RSP_TYPE_NO_PREFIX,
    AT_RSP_TYPE_INVALID    // No active request
} at_response_type_t;

typedef void (*at_unsol_callback_t)(char *rest, void *context);
typedef struct {
    char *prefix;
    at_unsol_callback_t callback;
} at_unsol_def_t;

int at_init(char *device, struct event_base *base, at_unsol_def_t *defs, int numDefs, void *context);
void at_shutdown(void);

void at_start_cmds(void);
at_result_t at_send_cmd(at_response_type_t rsp_type, char *prefix, char *opt, int timeout);
at_result_t at_send_cmd_1_int(at_response_type_t type, char *prefix, int arg, int timeout);
at_result_t at_send_cmd_2_int(at_response_type_t type, char *prefix, int arg1, int arg2, int timeout);
at_result_t at_send_query(at_response_type_t type, char *prefix, int timeout);

int at_rsp_error(void);
int at_rsp_num_lines(void);
char *at_rsp_next_line(void);
int at_tokenize_line(char *line, char tok, char **list, int len);
void at_end_cmds(void);

#endif // __AT_H__
