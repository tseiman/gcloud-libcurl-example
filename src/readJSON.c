
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
 *
 *  !! CAREFULL: !!
 * the buffer which is loaded from the file is kind of indexed with jsmn.h -
 * as we do not want to allocate new buffers for each element we just map 
 * the pointers into the struct - if we free this buffer also the config 
 * struct parameters are empty. To encapsulate the buffer in this function 
 * scope it is marked as static. The buffer is allocated in this function 
 * when it is loaded from file.
 * TO FREE THE CONFIG JSON BUFFER:
 * call this function with file and config pointer set to NULL
 * 
 * Parameter:
 * - char *file --> config file path and file   (set to NULL to free the JSON buffer)
 * - t_Config *config  --> config struct allocated externally  (set to NULL to free the JSON buffer)
 *
 * Returns: EXIT_SUCCESS (=0) 
 *          ENOENT if config file can't be opened
 *          ECANCELED if file can't be parsed
 *          EXIT_FAILURE on any other issue
 *
 **/
int readGCloudConfig(char *file, t_Config *config) {
    jsmn_parser p;
    jsmntok_t t[JSON_MAX_CONFIG_PARAM]; /* We expect no more than 32 JSON tokens */
    FILE *f = NULL;
    long length;
    int r, i;
    static char *jsonBuffer = NULL;     // we remember the buffer for the program lifetime 
                                        // because just map the pointers to the config struct

    if(!file && !config) {                         // we only free the buffer when file and config is null
        FREE(jsonBuffer);
        return EXIT_SUCCESS;
    }                                   // free the buffer is returning this function

    config->client_email = NULL;
    config->private_key = NULL;
    config->auth_uri = NULL;
    config->scope = NULL;
    config->token_uri = NULL;
    config->expire = 0;

    if (access(file, F_OK) != 0) {
        LOG_ERR( "Can't access JSON file: %s, failure: %s", file, strerror(errno));
//        errno = ENOENT; /* checking file exists and is accessible */
        return ENOENT;
    }

    f = fopen(file, "rb");

    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (!(jsonBuffer = MALLOC(length)))
            return EXIT_FAILURE;
        // jsonBuffer = MALLOC(length);

        if (jsonBuffer) {
            if (!fread(jsonBuffer, 1, length, f)) {
                LOG_ERR("cant read file %s", file);
                return ENOENT;
            }
        }
        fclose(f);
    }

    jsmn_init(&p);
    r = jsmn_parse(&p, jsonBuffer, strlen(jsonBuffer), t, JSON_MAX_CONFIG_PARAM);

    if (r < 0) {
        LOG_ERR("Failed to parse JSON: %d", r);
        return ECANCELED;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        LOG_ERR("JSON Object expected");
        return ECANCELED;
    }

    /* Loop over all keys of the root object */
    for (i = 1; i < r; i++) {
        jsonBuffer[t[i + 1].end] = '\0'; /* HACK - we just terminate strings in the buffer to avoid that we have to handle multible allocated buffers*/

        if (JSON_COMPARE("client_email")) {
            LOG_DEBUG("- client_email: %.*s", JSON_GET_VALUE);
            config->client_email = jsonBuffer + t[i + 1].start;
            i++;
        } else if (JSON_COMPARE("auth_uri")) {
            LOG_DEBUG("- auth_uri: %.*s", t[i + 1].end - t[i + 1].start, jsonBuffer + t[i + 1].start);
            config->auth_uri = jsonBuffer + t[i + 1].start;
            i++;
        } else if (JSON_COMPARE("scope")) {
            LOG_DEBUG("- scope: %.*s", t[i + 1].end - t[i + 1].start, jsonBuffer + t[i + 1].start);
            config->scope = jsonBuffer + t[i + 1].start;
            i++;
        } else if (JSON_COMPARE("token_uri")) {
            LOG_DEBUG("- token_uri: %.*s", t[i + 1].end - t[i + 1].start, jsonBuffer + t[i + 1].start);
            config->token_uri = jsonBuffer + t[i + 1].start;
            i++;
        } else if (JSON_COMPARE("private_key")) {

            LOG_DEBUG("- private_key: %.*s", t[i + 1].end - t[i + 1].start, jsonBuffer + t[i + 1].start);

            int offset = 0;
            for (int j = (t[i + 1].start); j <= (t[i + 1].end); ++j) { // this substitutes the "\n" string to a real newline in the private key
                if ((jsonBuffer[j] == '\\') && (jsonBuffer[j + 1] == 'n')) {
                    jsonBuffer[j - offset] = '\n'; // substitute the '\' from "\n" by a real newline
                    ++offset;                      // each place we find "\n" we shorten the string by 1 byte - because we exchange "\n" to a real newline
                    ++j;                           // jump over the 'n' from "\n"
                } else {
                    jsonBuffer[j - offset] = jsonBuffer[j]; // now because everything gets shorten by 1 byte when having found "\n" we need to move the rest of the buffer by 1 byte
                                                            // left for each found "\n"
                }
            }

            LOG_DEBUG("- private_key: %.*s", t[i + 1].end - t[i + 1].start, jsonBuffer + t[i + 1].start);

            config->private_key = jsonBuffer + t[i + 1].start;
            i++;
        } else if (JSON_COMPARE("expire")) {
            config->expire = strtoull(jsonBuffer + t[i + 1].start, NULL, 10);
            LOG_DEBUG("- expire: %lu", config->expire);
            i++;
        }
    }
    return EXIT_SUCCESS;
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
void cleanJSONConfig(void) {
    readGCloudConfig(NULL,NULL);
}

/** ****************************************************************************
 * Function:
 * Takes a JSON buffer returned from the HTTP POST response body and extracts
 * relevant parameters to t_CloudSessionState *sessionState.
 *
 * !! CAREFULL: !!
 * the buffer which is loaded from the is given by buffer parameter is kind of 
 * indexed with jsmn.h - as we do not want to allocate new buffers for each 
 * element we just map the pointers into the sessionState struct - if we free 
 * this buffer also the sessionState struct parameters are empty. 
 * To encapsulate the buffer in this function scope it is marked as static. 
 * The buffer is allocated in this function.
 * TO FREE THE Session JSON BUFFER:
 * call this function with buffer and sessionState pointer set to NULL

 * 
 * Parameter:
 * - char *buffer --> buffer with the HTTP response (JSON) (set to NULL for free the memory)
 * - t_CloudSessionState *sessionState  --> session struct allocated externally (set to NULL for free the memory
 *
 * Returns: EXIT_SUCCESS (=0) 
 *          ENOENT if config file can't be opened
 *          ECANCELED if file can't be parsed
 *          EXIT_FAILURE on any other issue
 *
 **/
int parseJWTTokenResponse(char *buffer, t_CloudSessionState *sessionState) {
    int result = EXIT_FAILURE;
    int r, i;
    jsmn_parser p;
    jsmntok_t t[JSON_MAX_SESSION_PARAM]; /* We expect no more than 32 JSON tokens */
    static char *jsonBuffer;
    

    
    if(!buffer && !sessionState) {      // we only free the buffer when file and config is null
        FREE(jsonBuffer);
        return EXIT_SUCCESS;
    }                                   // free the buffer is returning this function

    jsonBuffer = MALLOC(strlen(buffer));
    strcpy(jsonBuffer, buffer);


    jsmn_init(&p);
    r = jsmn_parse(&p, jsonBuffer, strlen(jsonBuffer), t, JSON_MAX_SESSION_PARAM);

    if (r < 0) {
        LOG_ERR("Failed to parse JSON: %d", r);
        return ECANCELED;
    }

    /* Assume the top-level element is an object */
    if (r < 1 || t[0].type != JSMN_OBJECT) {
        LOG_ERR("JSON Object expected");
        return ECANCELED;
    }

    for (i = 1; i < r; i++) {
        jsonBuffer[t[i + 1].end] = '\0'; /* HACK - we just terminate strings in the buffer to avoid that we have to handle multible allocated buffers*/

        if (JSON_COMPARE("expires_in")) {
            LOG_DEBUG("- expires_in: %.*s", JSON_GET_VALUE);
            sessionState->expires_in = strtoull(jsonBuffer + t[i + 1].start, NULL , 10);
            i++;
        } else if (JSON_COMPARE("token_type")) {
            LOG_DEBUG("- token_type: %.*s", JSON_GET_VALUE);
            sessionState->token_type = jsonBuffer + t[i + 1].start;
            i++;
        } else if (JSON_COMPARE("access_token")) {
            LOG_DEBUG("- access_token: %.*s", JSON_GET_VALUE);
            sessionState->access_token = jsonBuffer + t[i + 1].start;
            i++;
        }
    }
    return EXIT_SUCCESS;

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
void cleanJWTTokenResponse(void) {
    parseJWTTokenResponse(NULL,NULL);
}