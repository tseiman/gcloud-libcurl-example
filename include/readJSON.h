

/** ***************************************************************************
 *  ***************************************************************************
 *
 * readJSON.h is part of the project: FILLME 
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024 
 *
 * Description:
 *
 * check readJSON.c for further information
 *
 * ****************************************************************************
 * **************************************************************************** **/

#ifndef READ_JSON_H
#define READ_JSON_H
#include "session.h"



struct Config {
  char *client_email;
  char *private_key;
  char *auth_uri;
  char *scope;
  char *token_uri;
  char *pubsub_topic_url;
  unsigned long expire;

};
typedef struct Config t_Config;




int readGCloudConfig(char *file, t_Config* config);
void cleanJSONConfig(t_Config *config);

int parseJWTTokenResponse(char *buffer, t_CloudSessionState *sessionState);
void cleanJWTTokenResponse(t_CloudSessionState *sessionState);

int parsePublishResponse(char *jsonBuffer, t_CloudSessionState *sessionState);

#endif