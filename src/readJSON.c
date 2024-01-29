
/** ***************************************************************************
 *  ***************************************************************************
 *
 * readJSON.c is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 *
 *
 *
 * ****************************************************************************
 * **************************************************************************** **/

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "alloc.h"
#include "jsmn.h"
#include "messages.h"
#include "readJSON.h"
#include <htmlClient.h>

#define JSON_MAX_CONFIG_PARAM 32
#define JSON_MAX_SESSION_PARAM 32

#define JSON_GET_VALUE t[i + 1].end - t[i + 1].start, jsonBuffer + t[i + 1].start
#define JSON_COMPARE(parameter) jsoneq(jsonBuffer, &t[i],parameter)

#define ERROR_EXIT(code) LOG_ERR("ERROR - exiting"); result=code; goto EXIT;


#define JSON_ALLOCATE_AND_COPY_VALUE(field)  if(! (field = MALLOC(t[i + 1].end - t[i + 1].start + 1))) goto EXIT; \
              strncpy(field, jsonBuffer + t[i + 1].start, t[i + 1].end - t[i + 1].start); \
              field[t[i + 1].end - t[i + 1].start ] = '\0'; \
              LOG_DEBUG("- " #field ": %s", field);

#define JSON_CONFIG_FREE(field) FREE(config->field);

/** ****************************************************************************
 * Function: returns 
 *
 *
 * Parameter:
 * -
 * -
 * -
 *
 * Returns:
 *
 **/
static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start && strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return TRUE;
    }
    return FALSE;
}

/** ****************************************************************************
 * Function:
 * Takes the JSON config file which assembeld from the GCP service account 
 * configuration download and additional parameters (see sample JSON 
 * config file) and parses it. The relevant parameters are extracted 
 * and writen to the t_Config *config struct wich is externally allocated
 * each char* field of the config struct is allocated here and might be freed
 * with cleanJSONConfig()
 * 
 * Parameter:
 * - char *file --> config file path and file  
 * - t_Config *config  --> config struct allocated externally  
 *
 * Returns: EXIT_SUCCESS (=0) 
 *          ENOENT if config file can't be opened
 *          ECANCELED if file can't be parsed
 *          EXIT_FAILURE on any other issue
 *
 **/
int readGCloudConfig(char *file, t_Config *config) {
    int result = EXIT_FAILURE;
    jsmn_parser p;
    jsmntok_t t[JSON_MAX_CONFIG_PARAM]; /* We expect no more than 32 JSON tokens */
    FILE *f = NULL;
    long length;
    int r, i;
    static char *jsonBuffer = NULL;     // we remember the buffer for the program lifetime 
                                        // because just map the pointers to the config struct



    config->client_email = NULL;
    config->private_key = NULL;
    config->auth_uri = NULL;
    config->scope = NULL;
    config->token_uri = NULL;
    config->expire = 0;

    if (access(file, F_OK) != 0) {
        LOG_ERR( "Can't access JSON file: %s, failure: %s", file, strerror(errno));
        ERROR_EXIT(ENOENT);
    }

    f = fopen(file, "rb");

    
    if (!f) {
         LOG_ERR("file open failed %s", file);
         ERROR_EXIT(ENFILE)
    }
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (!(jsonBuffer = MALLOC(length))) { 
            LOG_ERR("Error allocate Memory");
            ERROR_EXIT(ENOMEM);
        }

        if (jsonBuffer) {
            if (!fread(jsonBuffer, 1, length, f)) {
                LOG_ERR("cant read file %s", file);
                ERROR_EXIT(ENOENT);
            }
        }
        fclose(f);
    
    jsmn_init(&p);
    r = jsmn_parse(&p, jsonBuffer, strlen(jsonBuffer), t, JSON_MAX_CONFIG_PARAM);

    if (r < 0) {
        LOG_ERR("Failed to parse JSON: %d", r);
        ERROR_EXIT(ECANCELED);
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        LOG_ERR("JSON Object expected");
        ERROR_EXIT(ECANCELED);
    }

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++) {

        if (JSON_COMPARE("client_email")) {
            JSON_ALLOCATE_AND_COPY_VALUE(config->client_email);
            i++;
        } else if (JSON_COMPARE("auth_uri")) {
            JSON_ALLOCATE_AND_COPY_VALUE(config->auth_uri);
            i++; 
        } else if (JSON_COMPARE("scope")) {
            JSON_ALLOCATE_AND_COPY_VALUE(config->scope);
            i++;
        } else if (JSON_COMPARE("token_uri")) {
            JSON_ALLOCATE_AND_COPY_VALUE(config->token_uri);
            i++;
        }  else if (JSON_COMPARE("pubsub_topic")) {
            JSON_ALLOCATE_AND_COPY_VALUE(config->pubsub_topic);
            i++;
        } else if (JSON_COMPARE("private_key")) {
            JSON_ALLOCATE_AND_COPY_VALUE(config->private_key);

            int offset = 0;
            for (int j = 0; j <= strlen(config->private_key); ++j) { // this substitutes the "\n" string to a real newline in the private key
                if ((config->private_key[j] == '\\') && (config->private_key[j + 1] == 'n')) {
                    config->private_key[j - offset] = '\n'; // substitute the '\' from "\n" by a real newline
                    ++offset;                      // each place we find "\n" we shorten the string by 1 byte - because we exchange "\n" to a real newline
                    ++j;                           // jump over the 'n' from "\n"
                } else {
                    config->private_key[j - offset] = config->private_key[j]; // now because everything gets shorten by 1 byte when having found "\n" we need to move the rest of the buffer by 1 byte
                                                            // left for each found "\n"
                }
            }
            i++;
        } else if (JSON_COMPARE("expire")) {
            config->expire = strtoull(jsonBuffer + t[i + 1].start, NULL, 10);
            LOG_DEBUG("- expire: %lu", config->expire);
            i++;
        }
           
    }

    result = EXIT_SUCCESS;
EXIT:
    FREE(jsonBuffer);
    return result;
}

/** ****************************************************************************
 * Function:
 * frees the JSON config buffer allocated in readGCloudConfig() above
 *
 * Parameter: none
 *     
 * Returns: none
 *
 **/
void cleanJSONConfig(t_Config *config) {
        JSON_CONFIG_FREE(client_email);
        JSON_CONFIG_FREE(private_key);
        JSON_CONFIG_FREE(auth_uri);
        JSON_CONFIG_FREE(scope);
        JSON_CONFIG_FREE(token_uri);
        JSON_CONFIG_FREE(pubsub_topic);
}

/** ****************************************************************************
 * Function:
 * Takes a JSON buffer returned from the HTTP POST response body and extracts
 * relevant parameters to t_CloudSessionState *sessionState.
 *
 * 
 * Parameter:
 * - char *buffer --> buffer with the HTTP response (JSON)
 * - t_CloudSessionState *sessionState  --> session struct allocated externally 
 *
 * Returns: EXIT_SUCCESS (=0) 
 *          ENOENT if config file can't be opened
 *          ECANCELED if file can't be parsed
 *          EXIT_FAILURE on any other issue
 *
 **/
int parseJWTTokenResponse(char *jsonBuffer, t_CloudSessionState *sessionState) {
    int result = EXIT_FAILURE;
    int r, i;
    jsmn_parser p;
    jsmntok_t t[JSON_MAX_SESSION_PARAM]; /* We expect no more than 32 JSON tokens */
   // static char *jsonBuffer;
    

    
    if(!jsonBuffer && !sessionState) {      // we only free the buffer when file and config is null
       // FREE(jsonBuffer);
        return EXIT_SUCCESS;
    }                                   // free the buffer is returning this function
/*
    if (!(jsonBuffer = MALLOC(strlen(buffer)))) { 
        LOG_ERR("Error allocate Memory");
        ERROR_EXIT(ENOMEM);
    }
    strcpy(jsonBuffer, buffer);
*/

    jsmn_init(&p);
    r = jsmn_parse(&p, jsonBuffer, strlen(jsonBuffer), t, JSON_MAX_SESSION_PARAM);

    if (r < 0) {
        LOG_ERR("Failed to parse JSON: %d", r);
        ERROR_EXIT(ECANCELED);
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        LOG_ERR("JSON Object expected");
        ERROR_EXIT(ECANCELED);
    }

    for (i = 1; i < r; i++) {
        jsonBuffer[t[i + 1].end] = '\0'; /* HACK - we just terminate strings in the buffer to avoid that we have to handle multible allocated buffers*/

        if (JSON_COMPARE("expires_in")) {
            LOG_DEBUG("- expires_in: %.*s", JSON_GET_VALUE);
            sessionState->expires_in = strtoull(jsonBuffer + t[i + 1].start, NULL , 10);
            i++;
        } else if (JSON_COMPARE("token_type")) {
            JSON_ALLOCATE_AND_COPY_VALUE(sessionState->token_type);
            i++;
        } else if (JSON_COMPARE("access_token")) {
            JSON_ALLOCATE_AND_COPY_VALUE(sessionState->access_token);
            i++;
        }
    }
    result = EXIT_SUCCESS;
EXIT:
 //   FREE(jsonBuffer);
    return result;

}

/** ****************************************************************************
 * Function:
 * frees the JSON config buffer allocated in parseJWTTokenResponse() above
 *
 * Parameter: none
 *     
 * Returns: none
 *
 **/
void cleanJWTTokenResponse(t_CloudSessionState *sessionState) {
    FREE(sessionState->token_type);
    FREE(sessionState->access_token);
}