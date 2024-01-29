
#ifndef READ_JSON_H
#define READ_JSON_H
#include "session.h"



struct Config {
  char *client_email;
  char *private_key;
  char *auth_uri;
  char *scope;
  char *token_uri;
  unsigned long expire;
};
typedef struct Config t_Config;




int readGCloudConfig(char *file, t_Config* config);
void cleanJSONConfig(void);

int parseJWTTokenResponse(char *buffer, t_CloudSessionState *sessionState);
void cleanJWTTokenResponse(void);

#endif