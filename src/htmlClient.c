
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
 * This is a basic example of how to upload JSON (String) via HTTP(S) to a
 * google cloud object, using service to service authentication with JWT
 *
 * ****************************************************************************
 * **************************************************************************** **/

#include "curl/curl.h"
#include <stdio.h>
#include <string.h>

#include "alloc.h"
#include "htmlClient.h"
#include "readJSON.h"

/* *************************************************************************** */

#define POST_JWT_PARAMETER "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="

struct responseBuffer {
    char *response;
    size_t size;
};
typedef struct responseBuffer responseBuffer_t;

/** ****************************************************************************
 * Function:
 * gets called when curl_easy_perform() gets a callback it expects
 * >void *clientp< to be set by
 * curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&httpResultBuffer);
 *
 * with the response from the server. In case of positive outcome it
 * receives the OAuth token and writes it to the config oauth_token parameter
 *
 * Parameter & Returns:
 * please check https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 * for further information
 *
 **/

static size_t http_cb(void *data, size_t size, size_t nmemb, void *clientp) {
    size_t realsize = size * nmemb;
    responseBuffer_t *mem = (responseBuffer_t *)clientp;

    char *ptr = REALLOC(mem->response, mem->size + realsize + 1);
    if (!ptr)
        return EXIT_FAILURE; /* out of memory! */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

/** ****************************************************************************
 * Function:
 * sends the JWT via HTTP(S) post to GCP and expects a callback
 * with the OAuth token
 *
 * Parameter:
 * - char *jwt         --> a pointer with the ready Base64url encoded JWT
 * - t_Config *config  --> the config struct containing all app
 *                         relevant parameters
 *
 * Returns: EXIT_FAILURE=1 or EXIT_SUCCESS=0
 *
 **/
int httpPostJWT(char *jwt, t_Config *config, t_CloudSessionState *sessionState) {

    CURL *curl;
    CURLcode res;
    char *postParam;
    long http_code = 0;
    responseBuffer_t httpResultBuffer = {0};
    int result = EXIT_FAILURE;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    if (!curl) {
        LOG_ERR("Init of Curl failed");
        goto ERROR_POST_JWT;
    }

    const char reqParam[] = POST_JWT_PARAMETER;
    if (!(postParam = MALLOC(strlen(reqParam) + strlen(jwt))))
        return EXIT_FAILURE;
    strcpy(postParam, reqParam);
    strcat(postParam, jwt);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&httpResultBuffer);

    curl_easy_setopt(curl, CURLOPT_URL, config->token_uri); // set the URL
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postParam);  // configure the POST data

    res = curl_easy_perform(curl); // Perform the request, res will get the return code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    LOG_DEBUG("JWT POSt HTTP Response Code %ld", http_code);

    if (res != CURLE_OK) // Check for errors
        LOG_ERR("curl_easy_perform()  failed: %s", curl_easy_strerror(res));
    curl_easy_cleanup(curl);

    LOG_DEBUG("HTTP Response: %s", httpResultBuffer.response);

    if (parseJWTTokenResponse(httpResultBuffer.response, sessionState)) {
        LOG_ERR("Parsing JSON Response on JWT Request failed.");
        goto ERROR_POST_JWT;
    }

    result = EXIT_SUCCESS;

ERROR_POST_JWT:
    curl_global_cleanup();
    FREE(postParam);
    FREE(httpResultBuffer.response);
    return result;
}
