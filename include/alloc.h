/** ***************************************************************************
 *  ***************************************************************************
 *
 * alloc.h is part of the project: FILLME 
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024 
 *
 * Description:
 *
 * Macros to handle Memory allocation - basically it helps in a very 
 * simple way debugging of memory issues
 *
 * ****************************************************************************
 * **************************************************************************** **/

#ifndef ALLOC_H
#define ALLOC_H

void *MALLOC(size_t size);
void *REALLOC(void *p, size_t size);
void FREE(void *p);


#endif