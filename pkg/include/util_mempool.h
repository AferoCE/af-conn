#ifndef UTIL_MEMPOOL_HEADER
#define UTIL_MEMPOOL_HEADER

#include "connectivity_util.h"

/* 2^n, currently, set it to 2^3 = 8 bytes alignment for double or long */
//#define MEM_BOUNDARY (sizeof(void *))
#define MEM_BOUNDARY 3
#define MEM_ALIGN(x) (((x + ((1 << MEM_BOUNDARY) - 1)) >> MEM_BOUNDARY) << MEM_BOUNDARY)

typedef struct util_mempool_defs_struct {
    int block_size;
    int group_size;
} util_mempool_defs;

void* util_mempool_alloc(void* mempool, int requested_size);
void util_mempool_free(void *data);

void* util_mempool_create(util_mempool_defs *def, int def_size);
void util_mempool_destroy(void *data);

void util_mempool_verify_test();
#endif