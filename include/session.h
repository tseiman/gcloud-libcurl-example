

#ifndef SESSION_H
#define SESSION_H

struct CloudSessionState {
    char *access_token;
    char *token_type;
    unsigned long int expires_in;
};
typedef struct CloudSessionState t_CloudSessionState;


#endif