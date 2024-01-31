/** ***************************************************************************
 *  ***************************************************************************
 *
 * alloc.c is part of the project: FILLME 
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024 
 *
 * Description:
 *
 * Handleing Memory allocation - basically it helps in a very 
 * simple way debugging of memory issues
 *
 * ****************************************************************************
 * **************************************************************************** **/

#include <stdlib.h>

#include "messages.h"

int alloc_counter;


void *MALLOC(size_t size) {
    void *pointer = NULL;
    ++alloc_counter; 
    if(! (pointer = malloc(size))) { 
        LOG_ERR("was not able to allocate %ld bytes, failed", (long int) size);
    } else MEM_DBG("Allocated %ld bytes at %p, %d different memory segments for different allocations allocated", (long int) size, pointer, alloc_counter);
    return pointer;
}

void *REALLOC(void *p, size_t size) {
    void  *pointer = NULL; 
    if(!p) ++alloc_counter; 
    if(! (pointer = realloc(p, size))) { 
        LOG_ERR("was not able to re-allocate %ld bytes, failed", (long int) size); 
    } else MEM_DBG("(Re-)Allocated %ld bytes at %p, %d different memory segments for different allocations allocated", (long int) size, pointer, alloc_counter); 
    return pointer;
}

void FREE(void *p) { 
    if(p) { 
        --alloc_counter; 
        free(p); 
        MEM_DBG("Freeing at %p, still to free %d",p, alloc_counter); 
        p = NULL; 
    } else MEM_DBG("Pointer %p never allocated", p); 
}

