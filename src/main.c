
/** ***************************************************************************
 *  ***************************************************************************
 *
 * htmlClient.c is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 *
 * This is a basic example of how to upload JSON (String) via HTTP(S) to a google
 * cloud object, using service to service authentication with JWT
 * This file implements the Program entrypoint and the CLI parameter handling.
 * Help Message is printed to STDOUT here too
 *
 * ****************************************************************************
 * **************************************************************************** **/

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "alloc.h"
#include "htmlClient.h"
#include "javaWebToken.h"
#include "messages.h"
#include "readJSON.h"
#include "base64url.h"
#include "dataSource.h"

int verbosity = 0;


int main(int argc, char **argv) {
    int index;
    int c;
    char *gCloudJSONFile = NULL;
    char *jwt = NULL;
    char *data; 
    int jwtResult = 0;
    int result = EXIT_FAILURE;
    int repeatJWT = 0;
    t_Config config = {0};
    t_CloudSessionState sessionState = {0};

    opterr = 0;

    if (argc < 2) {
        PRINT_MSG_HELP_AND_EXIT(argv[0]);
    }

    while ((c = getopt(argc, argv, "k:v:h")) != -1) {
        switch (c) {
        case 'k':
            gCloudJSONFile = optarg;
            continue;
        case 'v':
            verbosity = atoi(optarg);
            continue;
        case 'h':
        default:
            PRINT_MSG_HELP_AND_EXIT(argv[0]);
        }
    }

    if (gCloudJSONFile == NULL) {
        LOG_ERR("GCloud Key config file not given - exiting.");
        exit(EXIT_FAILURE);
    }

    LOG_INFO_MSG_WITH_OK("Loading file %s",gCloudJSONFile);
    if (readGCloudConfig(gCloudJSONFile, &config)) { 
        LOG_INFO_FAIL();
        goto EXIT;
    }
    LOG_INFO_OK();

    LOG_INFO_MSG_WITH_OK("Generate JWT");
    if (generateJWT(&jwt, &config)) { 
        LOG_INFO_FAIL();
        goto EXIT;
    }
    LOG_INFO_OK();

    LOG_INFO_MSG_WITH_OK("Request OAuth2 token from cloud service via HTTP POST and JWT");
    if (httpPostJWT(jwt, &config, &sessionState)) { 
        LOG_INFO_FAIL();
        goto EXIT;
    }
    LOG_INFO_OK();


    LOG_INFO_MSG_WITH_OK("Getting Data");
    if ( getData(&data, &config)) {
        LOG_INFO_FAIL();
        goto EXIT;
    }
    LOG_INFO_OK();

    LOG_INFO_MSG_WITH_OK("Sending data to GCP");
    if ( httpPostData(data, &config, &sessionState)) {
        LOG_INFO_FAIL();
        goto EXIT;
    }
    LOG_INFO_OK();


    LOG_INFO_MSG_WITH_OK("Got a message reponse with messageID=%lu", sessionState.messageID);
    if (!sessionState.messageID) {
        LOG_INFO_FAIL();
        goto EXIT;
    }
    LOG_INFO_OK();

    result = EXIT_SUCCESS;
EXIT:
    FREE(jwt);
    FREE(data);
    cleanJWTTokenResponse(&sessionState);
    cleanJSONConfig(&config);
    return result;
}
