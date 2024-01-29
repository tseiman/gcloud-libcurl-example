
/** ***************************************************************************
 *  ***************************************************************************
 *
 * htmlClient.h is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 *
 * This is a basic example of how to upload JSON (String) via HTTP(S) to a
 * google cloud object, using service to service authentication with JWT
 *
 * ****************************************************************************
 * **************************************************************************** **/

#ifndef HTMLCLIENT_H
#define HTMLCLIENT_H

#include "readJSON.h"
#include "session.h"


int httpPostJWT(char *jwt, t_Config *config, t_CloudSessionState *sessionState);


#endif