#ifndef UTIL_QUEUE_HEADER
#define UTIL_QUEUE_HEADER

typedef enum {
    UTIL_QUEUE_ERR_NONE = 0,
    UTIL_QUEUE_ERR_FULL,
    UTIL_QUEUE_ERR_EMPTY,
    UTIL_QUEUE_ERR_UNSPECIFIED,
    UTIL_QUEUE_ERR_INVALID_PARAM,
    UTIL_QUEUE_ERR_MAX,
} util_queue_error;

typedef void * util_queue_item;

void* util_queue_init(int element_size, int queue_size);
int util_queue_get_queue_size(void *_queue);
int util_queue_get_element_size(void *_queue);
int util_queue_add(void *queue, void *data, int data_len);
int util_queue_get_count(void *queue);
int util_queue_get_wait(void *_queue, void *data, int flag_wait);
void util_queue_destroy(void *queue);

#endif