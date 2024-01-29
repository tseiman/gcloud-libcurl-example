#ifndef ALLOC_H
#define ALLOC_H

#include "messages.h"
#include <stdlib.h>


int alloc_counter;

#define MALLOC(size) ({ \
    char *pointer = NULL; \
    ++alloc_counter; \
    if(! (pointer = malloc(size))) { \
        LOG_ERR("was not able to allocate %ld bytes, failed", (long int) size); \
    } else MEM_DBG("Allocated %ld bytes at %p, %d different memory segments for different allocations allocated", (long int) size, pointer, alloc_counter); \
    pointer; \
})

#define REALLOC(p, size) ({ \
    char *pointer = NULL; \
    if(!p) ++alloc_counter; \
    if(! (pointer = realloc(p, size))) { \
        LOG_ERR("was not able to re-allocate %ld bytes, failed", (long int) size); \
    } else MEM_DBG("(Re-)Allocated %ld bytes at %p, %d different memory segments for different allocations allocated", (long int) size, pointer, alloc_counter); \
    pointer; \
})

#define FREE(pointer) ({ \
    --alloc_counter; \
    if(pointer) free(pointer); \
    MEM_DBG("Freeing at %p, still to free %d",pointer, alloc_counter); \
})

#endif