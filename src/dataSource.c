
/** ***************************************************************************
 *  ***************************************************************************
 *
 * dataSource.c is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 *
 * this is just a data aqusition example substitute it
 * eventually with something reasonable
 * 
 * ****************************************************************************
 * **************************************************************************** **/

#include <string.h>
#include <time.h>
#include <stdio.h>

#include <linux/kernel.h>
#include <sys/sysinfo.h>

#include "alloc.h"
#include "readJSON.h"
#include "messages.h"

/* ---------------------------------------------------------------- */
/* CAREFUL changing the JSON Schema MUST be reflected on the cloud  */ 
/* if the schema is changed here without changing the schema at GCP */
/* we'll see an error reply on data send                            */
#define DEMO_DATA_FMT "{ \"localtime\": %lu , \"uptime\": %ld, \"totalram\": %lu, \"freeram\": %lu, \"proc_count\": %d, \"loadavarage1\": %lu, \"loadavarage5\": %lu, \"loadavarage15\": %lu, \"client_email\": \"%s\" }"

/** ****************************************************************************
 * Function: 
 * is obtaining some sysinfo data and assembles it to a JSON
 * as this is just an example data aquisition there is no sophisticated 
 * error handling   
 * 
 * Parameter:
 * - the buffer the JSON data has to go
 * - the configuration
 * 
 * Returns:
 *  Integer: EXIT_SUCCESS (=0) on successful outcome
 *           EXIT_FAILURE (1) on fail
 * 
 **/

int getData(char **buffer, t_Config *config) {

    int strLen =0;
    int res;
    struct sysinfo si;


    if( (res = sysinfo(&si))) {
        LOG_ERR("Sysinfo not succesful: %s %d", strerror(res), res);
        return EXIT_FAILURE;
    }
 
    strLen = snprintf(NULL, 0, DEMO_DATA_FMT, (unsigned long) time(NULL), si.uptime, si.totalram, si.freeram, si.procs, si.loads[0], si.loads[1], si.loads[2], config->client_email );
    if(! (*buffer = MALLOC(strLen + 2))) return EXIT_FAILURE;
    snprintf(*buffer, strLen +1, DEMO_DATA_FMT, (unsigned long) time(NULL), si.uptime, si.totalram, si.freeram, si.procs, si.loads[0], si.loads[1], si.loads[2], config->client_email );

    return EXIT_SUCCESS;
}