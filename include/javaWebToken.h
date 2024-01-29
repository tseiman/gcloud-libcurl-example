/** ***************************************************************************
 *  ***************************************************************************
 *
 * javaWebToken.h is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 *
 * Assembly of JWT
 * may check javaWebToken.c and 
 * https://developers.google.com/identity/protocols/oauth2/service-account#httprest 
 * for further information
 *
 * ****************************************************************************
 * **************************************************************************** **/

#include <readJSON.h>

#ifndef JAVA_WEB_TOKEN_H
#define JAVA_WEB_TOKEN_H

#define JWT_CLAIM_FORMAT_NEWLINE ""
#ifdef DEBUG
#define JWT_CLAIM_FORMAT_NEWLINE "\n"
#endif

/* 
    requires following parameters:
    char *iss   -->  The email address of the service account.
    char *scope	-->  A space-delimited list of the permissions that the application requests.
    char *aud	-->  A descriptor of the intended target of the assertion. When making an access token request this value is always https://oauth2.googleapis.com/token.
    int  exp	-->  The expiration time of the assertion, specified as seconds since 00:00:00 UTC, January 1, 1970. This value has a maximum of 1 hour after the issued time.
    int  iat	-->  The time the assertion was issued, specified as seconds since 00:00:00 UTC, January 1, 1970.
*/

#define JWT_CLAIM_FORMAT \
"{" JWT_CLAIM_FORMAT_NEWLINE \
" \"iss\": \"%s\"," JWT_CLAIM_FORMAT_NEWLINE \
" \"scope\": \"%s\"," JWT_CLAIM_FORMAT_NEWLINE \
" \"aud\":\"%s\"," JWT_CLAIM_FORMAT_NEWLINE \
" \"exp\":%lu," JWT_CLAIM_FORMAT_NEWLINE \
" \"iat\":%lu" JWT_CLAIM_FORMAT_NEWLINE \
"}"


int generateJWT(char **jwt, t_Config *config);


#endif