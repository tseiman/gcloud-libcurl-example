/** ***************************************************************************
 *  ***************************************************************************
 *
 * javaWebToken.c is part of the project: gcloud-libcurl-example
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024
 *
 * Description:
 *
 * Assembly of JWT
 * may check https://developers.google.com/identity/protocols/oauth2/service-account#httprest 
 * for further information
 * 
 * ****************************************************************************
 * **************************************************************************** **/

// scope https://www.googleapis.com/auth/pubsub

#include <string.h>
#include <time.h>
#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <base64url.h>
#include <messages.h>
#include <alloc.h>
#include <javaWebToken.h>
#include <readJSON.h>


#define JWT_HEADER "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"

#define JWT_CONFIG_CHECK_STR(parameter) if(config->parameter == NULL ) { LOG_ERR("\"" #parameter "\" is not defined - may it was missing in JSON config file ?");  goto JWT_GENERATE_ERROR; } 
#define JWT_CONFIG_CHECK_INT(parameter) if(config->parameter == 0 ) { LOG_ERR("\"" #parameter "\" is not defined - may it was missing in JSON config file ?");  goto JWT_GENERATE_ERROR; } 



/** ****************************************************************************
 * Function: 
 * signs the JWT header and claim
 * found here  https://stackoverflow.com/questions/55422628/how-to-convert-openssl-rsa-structure-to-char-and-back
 * and here found here  https://www.bmt-online.org/rsa-verify.html
 *  
 * Parameter:
 * - const void *buf     --> input data byte array
 * - size_t buf_len      --> input data length
 * - void *pkey          --> input private key: byte array of the PEM representation 
 * - size_t pkey_len     --> private key length
 * - void **out_sig      --> output signature block, allocated in the function 
 * - size_t *out_sig_len --> output signature length
 * 
 * Returns: Integer
 *  EXIT_SUCCESS (=0) if everything was OK
 *  EXIT_FAILURE (=1) if something failed
 * 
 **/
#ifndef WITH_OPENSSL3
int sign_data(const void *buf, size_t buf_len, void *pkey, size_t pkey_len, void **out_sig, size_t *out_sig_len) {

    int status = EXIT_SUCCESS;
    int rc = 1;
    BIO *b = NULL;
    RSA *r = NULL;
    unsigned char *sig = NULL;
    unsigned int sig_len = 0;

    SHA256_CTX sha_ctx = { 0 };
    unsigned char digest[SHA256_DIGEST_LENGTH];

    rc = SHA256_Init(&sha_ctx);
    if (1 != rc) { status = EXIT_FAILURE; goto SHA256_SIGN_ERROR; }

    rc = SHA256_Update(&sha_ctx, buf, buf_len);
    if (1 != rc) { status = EXIT_FAILURE; goto SHA256_SIGN_ERROR; }

    rc = SHA256_Final(digest, &sha_ctx);
    if (1 != rc) { status = EXIT_FAILURE; goto SHA256_SIGN_ERROR; }


    b = BIO_new_mem_buf(pkey, pkey_len);
    r = PEM_read_bio_RSAPrivateKey(b, NULL, NULL, NULL);

    sig = MALLOC(RSA_size(r) + 1);
    sig[RSA_size(r) + 1] = '\0';
    if (NULL == sig) { status = EXIT_FAILURE; goto SHA256_SIGN_ERROR; }

    rc = RSA_sign(NID_sha256, digest, sizeof digest, sig, &sig_len, r);
    if (1 != rc) { status = EXIT_FAILURE; goto SHA256_SIGN_ERROR; }
        
    *out_sig = sig;
    

    *out_sig_len = sig_len;

SHA256_SIGN_ERROR:
    if (NULL != r) RSA_free(r);
    if (NULL != b) BIO_free(b);
    if (EXIT_SUCCESS != status) FREE(sig); /* in case of failure: free allocated resource */
    if (1 != rc) LOG_ERR("OpenSSL error: %s", ERR_error_string(ERR_get_error(), NULL));

    return status;
}
#else
#endif


/** ****************************************************************************
 * Function: 
 * Generates and assembles a JWT
 * 
 * Parameter:
 * - char **jwt         --> here the allocated buffer for the 
 *                          JWT will be assigned (to be freed externally !)
 * - t_Config *config   --> the configuration struct
 * 
 * Returns: Integer
 * EXIT_SUCCESS (=0) on success
 * EXIT_FAILURE (!=0) or other 
 **/

int generateJWT(char **jwt, t_Config *config) {
    ssize_t encStrLen, strLen;
    char *jwtHeaderEnc = NULL;
    char *jwtClaim = NULL;
    char *jwtClaimEnc = NULL;
    char *strToSign_HeaderDotClaim = NULL;
    char *signatureOut = NULL;
    size_t signatureOutLen = 0;
    char *signatureB64 = NULL;
    int result = EXIT_FAILURE;


    /* check we have all parameters */

    JWT_CONFIG_CHECK_STR(client_email);
    JWT_CONFIG_CHECK_STR(private_key);
    JWT_CONFIG_CHECK_STR(auth_uri);
    JWT_CONFIG_CHECK_STR(scope);
    JWT_CONFIG_CHECK_STR(token_uri);
    JWT_CONFIG_CHECK_INT(expire);

    /* basic key sanity check */

    if ((! strstr(config->private_key, "----BEGIN") ) && (! strstr(config->private_key, "---- BEGIN")) ) {
        LOG_ERR("This doesn't look like a valid key: %s", config->private_key);
         goto JWT_GENERATE_ERROR;
    }

    /* Generate JWT Header */
    encStrLen = Base64encode_len(strlen(JWT_HEADER));
    if(! (jwtHeaderEnc = MALLOC(encStrLen)))  goto JWT_GENERATE_ERROR;
    Base64URLencode(jwtHeaderEnc,JWT_HEADER,strlen(JWT_HEADER));
    LOG_DEBUG("JWT Header:  %s\n JWT Header encoded:  %s",JWT_HEADER, jwtHeaderEnc);


    /* Generate JWT claim set */
    strLen = snprintf(NULL, 0, JWT_CLAIM_FORMAT, config->client_email,config->scope, config->token_uri,config->expire + (unsigned long) time(NULL), (unsigned long) time(NULL));
    if(! (jwtClaim = MALLOC(strLen + 2)))  goto JWT_GENERATE_ERROR;
    snprintf(jwtClaim, strLen + 1, JWT_CLAIM_FORMAT, config->client_email, config->scope, config->token_uri, config->expire + (unsigned long) time(NULL), (unsigned long) time(NULL) );
   
    encStrLen = Base64encode_len(strlen(jwtClaim));
    if(! (jwtClaimEnc = MALLOC(encStrLen))) goto JWT_GENERATE_ERROR;
    Base64URLencode(jwtClaimEnc,jwtClaim,strlen(jwtClaim));

    LOG_DEBUG("JWT Claim:  %s\n JWT Claim encoded:  %s",jwtClaim, jwtClaimEnc);

    /* concat the JWT header and the claim set */
    
    if(! (strToSign_HeaderDotClaim = MALLOC(strlen(jwtClaim) + 1 + strlen(jwtClaimEnc)))) goto JWT_GENERATE_ERROR;

    strcpy(strToSign_HeaderDotClaim, jwtHeaderEnc);
    strcat(strToSign_HeaderDotClaim, ".");
    strcat(strToSign_HeaderDotClaim, jwtClaimEnc);

    /* sign payload and convert it to Base64 */
    sign_data(strToSign_HeaderDotClaim, strlen(strToSign_HeaderDotClaim), config->private_key, strlen(config->private_key),(void*) &signatureOut, &signatureOutLen);
 
    encStrLen = Base64encode_len(signatureOutLen);
    if(! (signatureB64 = MALLOC(encStrLen))) goto JWT_GENERATE_ERROR;
    Base64URLencode(signatureB64,signatureOut,signatureOutLen);

    LOG_DEBUG("JWT signature (Base64 len: %ld,  signature binary out len: %ld):  %s",strlen(signatureB64), signatureOutLen , signatureB64);

    if(strlen(signatureB64) <342) {
        LOG_ERR("Generation from JWT signature failed !");
        goto JWT_GENERATE_ERROR;
    }

    /* Concat header + claim with signature */

    if(! (*jwt = MALLOC(strlen(strToSign_HeaderDotClaim) + 1 + strlen(signatureB64)))) goto JWT_GENERATE_ERROR;
    strcpy(*jwt, strToSign_HeaderDotClaim);
    strcat(*jwt, ".");
    strcat(*jwt, signatureB64);


    result = EXIT_SUCCESS;

JWT_GENERATE_ERROR:
    FREE(jwtHeaderEnc);
    FREE(jwtClaimEnc);
    FREE(jwtClaim);
    FREE(strToSign_HeaderDotClaim);
    FREE(signatureOut);
    FREE(signatureB64);
    
    return result;
}