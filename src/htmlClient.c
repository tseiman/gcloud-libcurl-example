
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
#include <errno.h>
#include <stdlib.h>

#include "alloc.h"
#include "htmlClient.h"
#include "readJSON.h"
#include "base64url.h"
#include "messages.h"

/* *************************************************************************** */

#define WC_ERROR_EXIT(code) { LOG_ERR("ERROR can't proceed. Exiting function."); result=code; goto EXIT; }
#define WC_ERROR_EXIT_ENOMEM { LOG_ERR("ERROR can't proceed, can't allocate memory."); result=ENOMEM; goto EXIT; }
#define POST_JWT_PARAMETER "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
#define POST_GCP_AUTH_HEADER_FORMAT "Authorization: %s %s"
#define POST_GCP_MESSAGE_FORMAT "{'messages': [{'data': '%s'}]}"

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
    const char reqParam[] = POST_JWT_PARAMETER;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    if (!curl) {
        LOG_ERR("Init of Curl failed");
        WC_ERROR_EXIT(ECANCELED);
    }


    if (!(postParam = MALLOC(strlen(reqParam) + strlen(jwt)))) WC_ERROR_EXIT_ENOMEM;

    strcpy(postParam, reqParam);
    strcat(postParam, jwt);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&httpResultBuffer);

    curl_easy_setopt(curl, CURLOPT_URL, config->token_uri); // set the URL
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postParam);  // configure the POST data

    res = curl_easy_perform(curl); // Perform the request, res will get the return code

    if (res != CURLE_OK) // Check for errors
        LOG_ERR("curl_easy_perform()  failed: %s", curl_easy_strerror(res));

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    LOG_DEBUG("JWT POSt HTTP Response Code %ld", http_code);

    curl_easy_cleanup(curl);

    LOG_DEBUG("HTTP Response: %s", httpResultBuffer.response);

    if (parseJWTTokenResponse(httpResultBuffer.response, sessionState)) {
        LOG_ERR("Parsing JSON Response on JWT Request failed.");
        WC_ERROR_EXIT(ECANCELED);
    }

    result = EXIT_SUCCESS;

EXIT:
    curl_global_cleanup();
    FREE(postParam);
    FREE(httpResultBuffer.response);
    return result;
}

/** ****************************************************************************
 * Function:
 * sends data via HTTP(S) post to GCP
 *
 * Parameter:
 * - char *data         --> a pointer with the data to be send to GCP
 * - t_Config *config   --> the config struct containing all app
 *                          relevant parameters
 * - t_CloudSessionState *sessionState -->
 *                          a pointer to the response JSON came back from
 *                          httpPostJWT().
 *
 * Returns: EXIT_FAILURE=1 or EXIT_SUCCESS=0
 *
 **/
int httpPostData(char *data, t_Config *config, t_CloudSessionState *sessionState) {
    int result = EXIT_FAILURE;
    int strLen = 0;
    CURL *curl;
    CURLcode res;
    long http_code = 0;
    char *postDataB64Buffer = NULL;
    char *postDataJSONBuffer = NULL;
    char *postDataAuthHeaderBuffer = NULL;
    struct curl_slist *headerList = NULL;
    responseBuffer_t httpResultBuffer = {0};

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();

    if (!curl) {
        LOG_ERR("Init of Curl failed");
        WC_ERROR_EXIT(ECANCELED);
    }
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&httpResultBuffer);
    
    curl_easy_setopt(curl, CURLOPT_URL, config->pubsub_topic_url); // set the URL



    strLen = snprintf(NULL, 0, POST_GCP_AUTH_HEADER_FORMAT, sessionState->token_type, sessionState->access_token);
    if(! (postDataAuthHeaderBuffer = MALLOC(strLen + 2))) WC_ERROR_EXIT_ENOMEM;
    snprintf(postDataAuthHeaderBuffer, strLen + 1, POST_GCP_AUTH_HEADER_FORMAT, sessionState->token_type, sessionState->access_token);
  
    headerList = curl_slist_append(headerList, "content-type: application/json");
    headerList = curl_slist_append(headerList,postDataAuthHeaderBuffer );
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);

    strLen = Base64encode_len(strlen(data));
    if(! (postDataB64Buffer = MALLOC(strLen))) WC_ERROR_EXIT_ENOMEM;
    Base64encode(postDataB64Buffer,data,strlen(data));


    strLen = snprintf(NULL, 0, POST_GCP_MESSAGE_FORMAT, postDataB64Buffer);
    if(! (postDataJSONBuffer = MALLOC(strLen + 2))) WC_ERROR_EXIT_ENOMEM;
    snprintf(postDataJSONBuffer, strLen + 1, POST_GCP_MESSAGE_FORMAT, postDataB64Buffer);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postDataJSONBuffer);  // configure the POST data
    res = curl_easy_perform(curl);                          // Perform the request, res will get the return code

    if (res != CURLE_OK) // Check for errors
        LOG_ERR("curl_easy_perform()  failed: %s", curl_easy_strerror(res));

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    LOG_DEBUG("JWT POSt HTTP Response Code %ld", http_code);

    if(http_code != 200) {
        LOG_ERR("Error when publishing data: \n[ERROR]   %s\n[ERROR]   Response:\n[ERROR]   %s",data,httpResultBuffer.response);
        WC_ERROR_EXIT(ECANCELED);
    }


    LOG_DEBUG("HTTP Response: %s", httpResultBuffer.response);
    result = EXIT_SUCCESS;
EXIT:
    curl_easy_cleanup(curl);
    curl_slist_free_all(headerList);
    curl_global_cleanup();
    FREE(httpResultBuffer.response);
    FREE(postDataB64Buffer);
    FREE(postDataJSONBuffer);
    FREE(postDataAuthHeaderBuffer);

    return result;
}