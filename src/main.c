
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

#include <alloc.h>
#include <htmlClient.h>
#include <javaWebToken.h>
#include <messages.h>
#include <readJSON.h>

#include <base64url.h>
#include <string.h>
int verbosity = 0;

int main(int argc, char **argv) {
    int   index;
    int   c;
    char *gCloudJSONFile  = NULL;
    char *jwt             = NULL;
    int   printJWT        = 0;
    int   jwtResult       = 0;
    int   result          = EXIT_FAILURE;
    int   repeatJWT       = 0;
    t_Config            config          = {0};
    t_CloudSessionState sessionState    = {0}; 

    opterr = 0;

    if (argc < 2) {
        PRINT_MSG_HELP_AND_EXIT(argv[0]);
    }

    while ((c = getopt(argc, argv, "k:v:hp")) != -1) {
        switch (c) {
        case 'k':
            gCloudJSONFile = optarg;
            continue;
        case 'v':
            verbosity = atoi(optarg);
            continue;
        case 'p':
            printJWT = 1;
            continue;
        case 'h':
        default:
            PRINT_MSG_HELP_AND_EXIT(argv[0]);
        }
    }

    if (gCloudJSONFile == NULL) {

        LOG_ERR("GCloud Key config file not given - exiting.");
        exit(EINVAL);
    }

    if (readGCloudConfig(gCloudJSONFile, &config)) {
        cleanJSONConfig();
        exit(EINVAL);
    }

    if (generateJWT(&jwt, &config))
        goto EXIT;
    LOG_INFO("JWT: (len:%ld) %s", strlen(jwt), jwt);

    if (printJWT)
        printf("%s", jwt);

    httpPostJWT(jwt, &config, &sessionState);

    result = EXIT_SUCCESS;
EXIT:
    FREE(jwt);
    cleanJSONConfig();
    cleanJWTTokenResponse();
    return result;
}
