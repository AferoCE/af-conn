#ifndef UTIL_EVENT_HEADER
#define  UTIL_EVENT_HEADER

#include <stdint.h>

typedef enum {
    EVENT_ATTR_DATA_ALLOCATED = 0,
    EVENT_ATTR_DATA_FILLED,
    EVENT_ATTR_MAX
} util_event_attr;

typedef struct util_event_struct {
    uint32_t id;
    uint32_t param;
    uint16_t attr;
    void *queue;
    int (*cb)(struct util_event_struct *event);
    void *data;
} util_event;

typedef struct {
    void *queue;
    int (*default_cb)(util_event *event);
} util_event_thread_info;

typedef int (*event_proc_cb)(struct util_event_struct *event);
#endif
