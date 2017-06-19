#ifndef CONNECTIVITY_UTIL
#define CONNECTIVITY_UTIL

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <ev.h>

#include "message_event.h"

typedef struct {
    int data_len;
    int key;
    char *data;
    void *extra;
} util_intstr_item;

#define INTSTR_ITEM(key, cmd, cb) {sizeof(cmd), key, cmd, (void *)(cb)}
#define CB_ITEM(req, cb)   INTSTR_ITEM(req, NULL, cb)
#define ITEM(id) {0, id, NULL, NULL}
#define INT_ITEM(key, info) {info, key, NULL, NULL}
#define STR_ITEM(key, str) {sizeof(str), key, str, NULL}


#define UTIL_INTSTRM_END -1

#define ARRAY_SIZE(x) (int)(sizeof(x) / sizeof(x[0]))

#define ARRAY_AND_SIZE(x) x, ARRAY_SIZE(x)

#define KLOG(...) printf(__VA_ARGS__)\

#define KLOG_WITH_LEVEL(level, ...) \
    { \
        if (util_check_bitmask(s_debug_level, level)) \
            KLOG(__VA_ARGS__); \
    }

#define KLOG_LEVEL_DEBUG (1 << 0)
#define KLOG_LEVEL_ERROR (1 << 1)
#define KLOG_LEVEL_INFO  (1 << 2)

#define KLOGD(...) KLOG_WITH_LEVEL(KLOG_LEVEL_DEBUG, __VA_ARGS__)
#define KLOGI(...) KLOG_WITH_LEVEL(KLOG_LEVEL_INFO, __VA_ARGS__)
#define KLOGE(...) KLOG_WITH_LEVEL(KLOG_LEVEL_ERROR, __VA_ARGS__)

#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = ptr;\
    (type *)( (char *)__mptr - offsetof(type,member) );})


util_intstr_item* intstr_find_by_str(char *data, 
                                     uint16_t data_len,
                                     util_intstr_item *item,
                                     int item_len);


util_intstr_item* intstr_find_by_key(int key, 
                                     util_intstr_item *item,
                                     int item_len) ;

static inline char* intstr_get_str_by_key(int key, 
                                          util_intstr_item *item,
                                          int item_len)
{
    util_intstr_item *result;

    result = intstr_find_by_key(key, item, item_len);
    if (result != NULL)
        return result->data;

    return NULL;
}

static inline int int_str_lookup_item_get_data_len(util_intstr_item *item)
{
    return (item == NULL) ? -1 : item->data_len;
}

static inline void util_write_u8(uint8_t **buf, uint8_t val)
{
    *((*buf)++) = val;
}

static inline uint8_t util_read_u8(uint8_t **buf)
{
    return *((*buf)++);
}

#ifdef ORDER_BIG_ENDIAN
static inline void util_write_u16(uint8_t **buf, uint16_t val)
{
    *((*buf)++) = (val >> 8) & 0xFF;
    *((*buV f)++) = val & 0xFF;
}

static inline uint16_t util_read_u16(uint8_t **buf)
{
    uint16_t val;

    val  = (*(*buf)++) << 8;
    val |= *(*buf)++;

    return val;
}
#else

static inline void util_write_u16(uint8_t **buf, uint16_t val)
{
    
    *((*buf)++) = val & 0xFF;
    *((*buf)++) = (val >> 8) & 0xFF;

}

static inline uint16_t util_read_u16(uint8_t **buf)
{
    uint16_t val;

    val  = *(*buf)++;
    val |= (*(*buf)++) << 8;

    return val;
}
#endif

static uint8_t inline util_u8_clr_bit(uint8_t val, uint8_t bit_pos)
{
    return val & ~(1 << bit_pos);
}

static uint8_t inline util_u8_set_bit(uint8_t val, uint8_t bit_pos)
{
    return val | (1 << bit_pos);
}

static uint8_t inline util_u8_chk_bit(uint8_t val, uint8_t bit_pos)
{
    return (1 << bit_pos) & val;
}

static uint16_t inline util_u16_set_bit(uint16_t val, uint16_t bit_pos)
{
    return val | (1 << bit_pos);
}

static uint16_t inline util_u16_chk_bit(uint16_t val, uint16_t bit_pos)
{
    return (1 << bit_pos) & val;
}

static uint32_t inline util_set_bit(uint32_t val, uint16_t bit_pos)
{
    return val | (1 << bit_pos);
}

static uint32_t inline util_chk_bit(uint32_t val, uint32_t bit_pos)
{
    return (1 << bit_pos) & val;
}

static inline int util_u32_verify_single_bit_set(uint32_t val)
{
    if (val == 0 || ((val & (val - 1)) != 0))
        return -1;

    return 0;
}

static inline char* util_strncpy(char *dest, char *src, uint16_t copy_len)
{
    if (src == NULL) {
        memset(dest, 0, copy_len);
        return dest;
    }

    strncpy(dest, src, copy_len);

    if (dest[copy_len - 1] != '\0')
        dest[copy_len - 1] = '\0';

    return dest;
}

static inline int util_check_bitmask(uint32_t val, uint32_t mask)
{
    return ((val & mask) == mask);
}

static inline int util_check_bitmask_u16(uint16_t val, uint16_t mask)
{
    return ((val & mask) == mask);
}

static inline int util_check_bitmask_u8(uint8_t val, uint8_t mask)
{
    return ((val & mask) == mask);
}

typedef enum {
    AT_REQ_QUERY = 0,
    AT_REQ_WRITE,
    AT_REQ_WRITE_2INT,
    AT_REQ_EXECUTE,
    AT_REQ_EXECUTE_SIMPLE,
    AT_REQ_TEST,
    AT_REQ_TYPE_MAX
} at_req_type;

typedef struct {
    uint8_t rsp_type;
    uint8_t req_type;
    int cmd;
    int opt1;
    int opt2;
} at_req_generic;

typedef struct {
    uint32_t id;
} util_tbl_hdr;

#define UTILTBL_PARAM_FILL(array) (array), ARRAY_SIZE(array), sizeof(*(array)

typedef enum {
    UTIL_TBL_OP_ADD,
    UTIL_TBL_OP_REMOVE,
    UTIL_TBL_OP_MAX
} util_tbl_op;

/* simple list functions */
typedef struct util_list_node_struct {
    struct util_list_node_struct  *next;
    void *data;
} util_list_node;

int util_list_add_simple(void **root, void *next);
void* util_list_add(void *mempool, void **root, int node_len);
util_list_node* util_list_add_node(void *mempool, void **root, int node_len);
void util_list_free(void **root, int free_data);
void* util_list_remove(void **root, void *target);
void util_list_move_to_next(void **root);

/* string functions */
void* util_str_starts_with_ext(char **src, uint8_t* p, int struct_len, int list_len);

void* util_str_starts_with(char **src, char** prefix_list, int list_len);

int util_str_tokenize(char *line, char **list, int len);

int util_str_dec_to_bin(char *str, int len);

/* simple handler for message loop */
void* util_evloop_thread(void *data);
void* util_event_thread(void * data);

/* Task manager */

typedef struct {
    uint16_t        in_len;     /* length of IN param */
    uint16_t        out_len;    /* length of OUT param */
    int             status;     /* user can use this to indicate exec status */
    void            *out;       /* output param */
    void            *in;        /* input param */ 
    void            *token;     /* token for identification purpose */
} util_task_ctl_user;

typedef int (*util_task_cb) (util_task_ctl_user *task_user, 
                             uint8_t *data, uint16_t data_len);

typedef int (*util_task_final_cb) (int status, util_task_ctl_user *task_user);

typedef struct {
    uint8_t      attr;
    util_task_cb req;
    util_task_cb rsp;
    intptr_t     data;
} util_task_stage;

typedef enum {
    UTIL_STAGE_0,
    UTIL_STAGE_1, 
    UTIL_STAGE_2, 
    UTIL_STAGE_3, 
    UTIL_STAGE_4, 
    UTIL_STAGE_5, 
    UTIL_STAGE_6, 
    UTIL_STAGE_7, 
    UTIL_STAGE_8, 
    UTIL_STAGE_9, 
    UTIL_STAGE_MAX
} util_stage_index;

typedef enum {
    UTIL_TASK_STAGE_FINAL = 0,
    UTIL_TASK_STAGE_REQ_SENT,
    UTIL_TASK_STAGE_REQ_ONLY, /* only req cb will be invoked */
    UTIL_TASK_STAGE_NESTED_TASK, /* thi stage will invoke a task */
    UTIL_TASK_STAGE_NESTED_TASK_FREED,
    UTIL_TASK_STAGE_ATTR_MAX
} util_task_stage_attr;

typedef enum {
    UTIL_TASK_END_ERROR,
    UTIL_TASK_END_SUCCESS,
    UTIL_TASK_READY,
    UTIL_TASK_ATTR_MAX
} util_task_attr;

typedef struct {
    uint8_t             attr;
    uint8_t             stage_cnt;  /* total number of stages */
    uint8_t             stage_idx;  /* index for current stage */
    util_task_stage     *stage;     /* array of stages */
    util_task_final_cb  final;      /* final cb for current task */
    util_task_final_cb  final_post; /* cb to perform io clean up */
    void                *io;        /* how IO is performed */
    util_task_ctl_user  *parent;    /* parent node */
} util_task_ctl_core;

typedef struct {
    util_task_ctl_core core;
    util_task_ctl_user user;
} util_task_ctl;

typedef enum {
    TASK_START_SUCCESS = 0,
    TASK_START_NO_OP,
    TASK_START_FAILURE
} task_start_result;

static inline void util_task_set_user_inout(util_task_ctl_user *user_ctl,
                                            void *in, int in_len, void *out, int out_len)
{
    user_ctl->in = in;
    user_ctl->in_len = in_len;
    user_ctl->out = out;
    user_ctl->out_len = out_len;
}

#define STAGE(req, rsp, data) {0, req, rsp, (intptr_t)data}

#define STAGE_SIMPLE(req, rsp) {0, req, rsp, 0}

#define STAGE_REQ_ONLY(req, data) \
    {1 << UTIL_TASK_STAGE_REQ_ONLY, req, NULL, (intptr_t)data}

#define STAGE_TASK(task)  \
    {1 << UTIL_TASK_STAGE_NESTED_TASK, (util_task_cb)(task), NULL, ARRAY_SIZE(task)}

#define STAGE_FINAL(final, post) \
    {1 << UTIL_TASK_STAGE_FINAL, (util_task_cb)final, (util_task_cb)post, 0}


int util_task_set_stage(util_task_ctl_user *user, void* mempool,
                        util_task_stage *stage, int num_stage);

int util_task_invoke_rsp(util_task_ctl_user *user);

int util_task_invoke_req(util_task_ctl_user *user);

void* util_task_get_io(util_task_ctl_user *user);

int util_task_set_io(util_task_ctl_user *user, void *io);

int util_task_is_ready(util_task_ctl_user *user);

void util_task_free(util_task_ctl_user *user);

util_task_ctl_user *util_task_create(void *mempool, util_task_ctl_user *parent);

void util_task_terminate(util_task_ctl_user *task_user, int success);

util_task_ctl_user* util_task_get_child_task(util_task_ctl_user *parent, void* task_ptr);

void util_task_stage_done(util_task_ctl_user *user);

/**/
int util_task_set_stages_generic(util_task_stage *stage, int num_stage, 
                                 at_req_generic **data);

int util_task_set_stage_data(util_task_stage *stage, int num_stage, 
                             int key, void *data);

typedef struct {
    uint16_t         tbl_size;
    util_intstr_item *tbl;
    void             *mempool;
} util_event_cb_manager;

typedef int (*util_event_cb)(void *data, int datalen);

util_event* util_event_create(void *mempool, void *queue, int id, void *data);

int util_event_get_and_send(void *mempool, void *queue, event_proc_cb cb,
                            int eventid, void *data);

int util_event_send(util_event *event);

int util_event_register(util_event_cb_manager *manager, int event, util_event_cb cb);

void util_event_notify(util_event_cb_manager  *manager, int event, void *data,
                       int datalen);


typedef struct {
    uint16_t queue_entry_cnt;
    uint16_t queue_entry_size;
    uint16_t pool_def_size;
    util_mempool_defs *pool_def;
} module_base_param;

typedef struct {
    void                  *queue;
    void                  *mempool;
    ipc_context           *ipc;
} module_base;

typedef struct {
    module_base *base;
    ipc_ep      ep;
} module_ipc_base;

#endif
