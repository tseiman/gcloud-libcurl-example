
/** ***************************************************************************
 *  ***************************************************************************
 *
 * session.h is part of the project: FILLME 
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024 
 *
 * Description:
 *
 * here information are stored wich are returned by the GCP service 
 * from OAuth request with JWT for the next data publish request
 * This struct is in a separate file as it would be mutually included 
 * otherwise
 *
 * ****************************************************************************
 * **************************************************************************** **/

#ifndef SESSION_H
#define SESSION_H

struct CloudSessionState {
    char *access_token;
    char *token_type;
    unsigned long int expires_in;
};
typedef struct CloudSessionState t_CloudSessionState;


#endif