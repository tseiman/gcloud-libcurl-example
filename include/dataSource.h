
/** ***************************************************************************
 *  ***************************************************************************
 *
 * dataSource.h is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 * see dataSource.c for more information
 *  
 * ****************************************************************************
 * **************************************************************************** **/


#ifndef DATA_SOURCE_H
#define DATA_SOURCE_H

#include "readJSON.h"

int getData(char **buffer, t_Config *config);

#endif