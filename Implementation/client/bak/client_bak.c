#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "../common.h"

#define FAIL    -1
#define h_addr h_addr_list[0] /* for backward compatibility */

#define ECDSA_CLNT_PUB_KEY_PATH "clnt.pub"



struct ssl_cipher_st_test {
    uint32_t valid;
    const char *name;           /* text name */
    const char *stdname;        /* RFC name */
    uint32_t id;                /* id, 4 bytes, first is version */
    /*
     * changed in 1.0.0: these four used to be portions of a single value
     * 'algorithms'
     */
    uint32_t algorithm_mkey;    /* key exchange algorithm */
    uint32_t algorithm_auth;    /* server authentication */
    uint32_t algorithm_enc;     /* symmetric encryption */
    uint32_t algorithm_mac;     /* symmetric authentication */
    int min_tls;                /* minimum SSL/TLS protocol version */
    int max_tls;                /* maximum SSL/TLS protocol version */
    int min_dtls;               /* minimum DTLS protocol version */
    int max_dtls;               /* maximum DTLS protocol version */
    uint32_t algo_strength;     /* strength and export flags */
    uint32_t algorithm2;        /* Extra flags */
    int32_t strength_bits;      /* Number of bits really used */
    uint32_t alg_bits;          /* Number of bits for algorithm */
};

struct Person {
    char name[50];
    int age;
    float height;
};


/****************************************************************************
                            *   Callback functions   * 
 ****************************************************************************/


/****************************************************************************
                            *   User-defined functions   * 
****************************************************************************/

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();                           // Load cryptos, et.al.
    SSL_load_error_strings();                               // Bring in and register error messages
    
    method = TLSv1_2_client_method();                       // Create new client-method instance
    //method = TLS_client_method();                         // Create new client-method instance
    
    ctx = SSL_CTX_new(method);                              // Create new context
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);     // set TLS version
    printf("TLS version:: %d\n\n", SSL_CTX_get_max_proto_version(ctx));
    
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL ){
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){
        close(sd);
        perror(hostname);
        abort();
    }
    printf("!!!!!!OpenConnection\n");
    return sd;
}

void ShowServerCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);   // get the server's certificate

    // test for combined certificate. save in file.
    //FILE *outputFile = fopen("receivved.pem", "w");
    //if (PEM_write_X509(outputFile, cert) == 0) {
    //    perror("Error writing certificate to file");
    //    fclose(outputFile);
    //    X509_free(cert);
    //    SSL_free(ssl);
    //    return -1;
    //}
    //fclose(outputFile);


    // Check server's public key in certificate (START)
    EVP_PKEY *pubkey;

    pubkey = X509_get_pubkey(cert);
    //printf("Server Public key Description:: %s \n", EVP_PKEY_get0_description(pubkey));
    //printf("Server Public key Type Name:: %s \n", EVP_PKEY_get0_type_name(pubkey));
    printf("Server Public key Bits:: %d \n", EVP_PKEY_bits(pubkey));
    
    //EC_KEY *eckey;
    //eckey = EVP_PKEY_get1_EC_KEY(pubkey);
        
    //FILE *f;
    //int result;
    //f = fopen("key.pem", "wb");
    //result = PEM_write_PUBKEY(f, pubkey);
    // Check server's public key in certificate (END)

    if ( cert != NULL ){
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

/****************************************************************************
                            *   Callback functions   * 
 ****************************************************************************/

static int ext_add_cb(SSL *s, unsigned int ext_type,
                      const unsigned char **out,
                      size_t *outlen, int *al, void *add_arg)
{
    const char *rtnVal;
    switch (ext_type) {
        case 1000:
            printf("[client] 1000, ext_add_cb from client!\n");
            rtnVal = read_from_file(ECDSA_CLNT_PUB_KEY_PATH);
            *out = (const unsigned char*) rtnVal;
            printf("out value:: %s\n",*out);
            *outlen = strlen(rtnVal);
            printf("out len:: %d\n",*outlen);
            break;
        case 2000:
            printf("[client] 2000, ext_add_cb from client!\n");
            rtnVal = "give me warrant";
            *out = (const unsigned char*) rtnVal;
            printf("out value:: %s\n",*out);
            *outlen = strlen(rtnVal);
            printf("out len:: %d\n",*outlen);
            break;
        case 3000:
            printf("[client] 3000, ext_add_cb from client!\n");
            rtnVal = "give me pub key by client";
            *out = (const unsigned char*) rtnVal;
            printf("out value:: %s\n",*out);
            *outlen = strlen(rtnVal);
            printf("out len:: %d\n",*outlen);
            break;
        default:
            printf("[Client] Default\n");
            break;
    }
    return 1;
    //switch (ext_type) {
    //    case 1000:
    //        printf("[Client] 1000, ext_add_cb from client called!\n");
    //        const char *rtnVal;
    //        //rtnVal=extractPubKey();
    //        rtnVal="client message";
    //        *out = (const unsigned char*) rtnVal;
    //        printf("out value:: %s\n",*out);
    //        *outlen = strlen(rtnVal);
    //        printf("out len:: %d\n",*outlen);
    //        break;
    //    case 65280:
    //        printf("[Client] ext_add_cb from client called!\n");
    //        printf("%d\n", *(int *) add_arg);
    //        break;
    //    default:
    //        printf("[Client] Default\n");
    //        break;
    //}
    //return 1;
}

static void ext_free_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *out, void *add_arg)
{
    printf("[client] ext_free_cb from server called \n");
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
{
    printf("[client] ext_parse_cb from server called!\n");
    switch (ext_type) {
        case 1000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive proxy-delegation
            printf("in value size:: %d\n", inlen);
            write_to_file("proxy-delegation.txt", in);
            break;
        case 2000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive warrant
            printf("in value size:: %d\n", inlen);
            write_to_file("warrant.txt", in);
            break;
        case 3000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive server public key
            printf("in value size:: %d\n", inlen);
            write_to_file("srvr.pub", in);
            break;    
        case 4000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive middlebox public key
            printf("in value size:: %d\n", inlen);
            write_to_file("mb.pub", in);
            break;        
    }
    return 1;
}


int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    char acClientRequest[1024] = {0};
    int bytes;
    char *hostname, *portnum;
    if ( count != 3 ){
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
    ctx = InitCTX();

    int result = SSL_CTX_add_client_custom_ext(ctx, 3000, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);
    
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);                 /* create new SSL connection state */
    SSL_set_fd(ssl, server);            /* attach the socket descriptor */
    printf("Set SSL andSocket connection!! \n");
    //ssl_set_test   
    SSL_set_testaddvar(ssl, 77777);
    int test = SSL_get_testaddvar(ssl);
    printf("client.c test value is :: %d\n", test);
        
    //ssl->test_add_var = 100;
    test_in_ssl_lib(ssl);


    if ( SSL_connect(ssl) == FAIL )     /* perform the connection */
        ERR_print_errors_fp(stderr);
    else{
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = 
    "<Body>\
        <UserName>%s<UserName>\
        <Password>%s<Password>\
    <\\Body>";
        printf("==== After Connection ====\n");
        const unsigned char *bufCiphers;
        size_t lenCiphers = SSL_client_hello_get0_ciphers(ssl, &bufCiphers);
        const unsigned char *bufId;
        size_t lenId = SSL_client_hello_get0_session_id(ssl, &bufId);
        const unsigned char *bufRandom;
        size_t lenRandom = SSL_client_hello_get0_session_id(ssl, &bufRandom);

        printf("[%s] \n", SSL_get_cipher_name(ssl));    // connection 후 negotiated된 cipher list name을 가져옴.
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);
        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);   // construct reply 
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        printf("TLS version:: %d\n",SSL_version(ssl));
        
        ShowServerCerts(ssl);                                       // get server certification
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));    // encrypt & send message
        bytes = SSL_read(ssl, buf, sizeof(buf));                    // get reply & decrypt
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        //VerifySign(buf, ssl);
        SSL_free(ssl);          // release connection state
    }
    close(server);              // close socket
    SSL_CTX_free(ctx);          // release context
    return 0;
}

/*
void VerifySign(char *base64Sign, SSL* ssl)
{
    // plaintext
    unsigned char *concatText="hello";
    
    // decode base64 signature
    unsigned char *decodedSign;
    size_t decodedSignLen;
    Base64Decode(base64Sign, &decodedSign, &decodedSignLen);
    printf("decoded signature:: %s\n", decodedSign);
    printf("decoded signlen:: %d\n", decodedSignLen);

    printf("=========decoded signature==========\n");
    for (size_t i = 0; i < decodedSignLen; i++) {
        printf("%02x", decodedSign[i]);
    }
    printf("\n");

    //// get public key #1. verify return 0
    //X509 *cert; 
    //cert = SSL_get_peer_certificate(ssl);   // get the server's certificate 
    //EVP_PKEY *pubkey = X509_get_pubkey(cert);

    // get public key #3. 
    X509 *cert; 
    cert = SSL_get_peer_certificate(ssl);   // get the server's certificate 
    EVP_PKEY *pubkey = X509_get_pubkey(cert);

    // start verification
    EVP_MD_CTX *md_ctx_verify = EVP_MD_CTX_new();

    if ( EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sha256(), NULL, pubkey) <= 0 ){
        printf("EVP_DigestVerifyInit\n");
        return 0 ;
    }

    if ( EVP_DigestVerifyUpdate(md_ctx_verify, concatText, strlen(concatText)) <= 0 ){
        printf("EVP_DigestVerifyUpdate\n");
        return 0 ;
    }
    printf("verification update\n");

    int verifyResult = EVP_DigestVerifyFinal(md_ctx_verify, decodedSign, decodedSignLen);  //signlen
    if ( verifyResult <= 0 ){
        printf("EVP_DigestVerifyFinal failed....\n");
        printf("EVP_DIGEST VERIFY RESULT:: %d\n", verifyResult);
        return 0;
    }
    printf("verification final\n");
    printf("EVP_DIGEST VERIFY RESULT:: %d\n", verifyResult);

    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_free(md_ctx_verify);
//    OPENSSL_cleanup();
}
*/