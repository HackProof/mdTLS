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
#include "../module/proxy.h"


#define FAIL    -1
#define h_addr h_addr_list[0] /* for backward compatibility */
#define ECDSA_PUB_KEY_PATH "clnt-side/mb_c.pub"
#define ECDSA_PRIV_KEY_PATH "clnt-side/mb_c.pri"
#define MB_C_T_PATH "clnt-side/mb_c_t.txt"
#define MB_C_MSG_PATH "clnt-side/part_of_mb_cert_msg.txt"

struct  ssl_cipher_st_test{
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


/****************************************************************************
                            *   User-defined functions   * 
****************************************************************************/

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();                           // Load cryptos, et.al.
    SSL_load_error_strings();                               // Bring in and register error messages
    
    method = TLSv1_2_client_method();                     // Create new client-method instance
    //method = TLS_client_method();                           // Create new client-method instance
    
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
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    printf("!!!!!!OpenConnection\n");
    return sd;
}

void gen_proxy_sign_key(const char *param_proxy_del, const char *param_warrant, const char *param_srvr_pubkey)
{
    printf("proxy_del:: %s\n", param_proxy_del);
    //printf("warrant:: %s\n", warrant);
    //printf("srvr_pubkey:: %s\n", srvr_pubkey);

    char *Q_s = param_srvr_pubkey;
    char *Q_mb = read_from_file(ECDSA_PUB_KEY_PATH);
    char *id_mb = "mbc";
    char *warrant = param_warrant;

    const char *msg = concat_str(Q_s, Q_mb, id_mb, warrant);

    EC_KEY *srvr_keypairs = get_ECKey_public_from_PEM(Q_s);
    EC_KEY *mb_keypairs = get_ECKey_public_from_PEM(Q_mb);

    // set middlbox's private key PEM -> EC_KEY
    BIO *bio = BIO_new_mem_buf(read_from_file(ECDSA_PRIV_KEY_PATH), -1);
    if (bio == NULL) {
        perror("BIO_new_mem_buf failed");
        //handleErrors();
    }
    mb_keypairs = PEM_read_bio_ECPrivateKey(bio, &mb_keypairs, NULL, NULL);
    if (mb_keypairs == NULL) {
        perror("PEM_read_bio_ECPrivateKey failed");
       // handleErrors();
    }
    BIO_free(bio);
    // test middlebox private key in EC_KEY
    //const BIGNUM *privateKeyBN = EC_KEY_get0_private_key(mb_keypairs);
    //if (privateKeyBN == NULL) {
    //    perror("EC_KEY_get0_private_key failed");
    //    //handleErrors();
    //    return NULL;
    //}

    char str_x_Y_d[1000], str_s_d[1000];

    // split delegation signature (x_Y_d, s_d)
    if (sscanf(param_proxy_del, "%s %s", str_x_Y_d, str_s_d) != 2) {
        fprintf(stderr, "parse string fail\n");
        return NULL;
    }

    //printf("r = x_Y_d ::: %s\n", r);

    BIGNUM *x_Y_d = BN_new();
    BIGNUM *s_d = BN_new();
    BN_hex2bn(&x_Y_d, str_x_Y_d);
    BN_hex2bn(&s_d, str_s_d);

    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    BN_print(bio_out, x_Y_d);
    BIO_printf(bio_out, " ::x_Y_d:: \n");
    BN_print(bio_out, s_d);
    BIO_printf(bio_out, " ::s_d:: \n");

    const BIGNUM *t, *r_num, *c_num;    
    proxy_signing_key(msg, warrant, srvr_keypairs, mb_keypairs, x_Y_d, &t, &r_num, &c_num);

    BN_print(bio_out, t);
    BIO_printf(bio_out, " ::proxy signing key t:: \n");
    BN_print(bio_out, r_num);
    BIO_printf(bio_out, " ::r_num from proxy_signing key():: \n");

    // save t(proxy signing key) to file
    write_to_file(MB_C_T_PATH, BN_bn2hex(t));   // later used when generate mb cert
    
    // save Q_S||ID_MBi||Q_MBi||ω||x_Y_d||s_d||r to file
    // Q_S||ID_MBi||Q_MBi||ω == msg
    // r == r_num
    char *str_r = BN_bn2hex(r_num);
    char *part_of_mb_cert_msg = concat_str(msg, str_x_Y_d, str_s_d, str_r);
    write_to_file(MB_C_MSG_PATH, part_of_mb_cert_msg);
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
    // test for combined certificate. save in file. end.


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
            printf("[mb_c] 1000, ext_add_cb from mb_c!\n");
            rtnVal = read_from_file(ECDSA_PUB_KEY_PATH);
            *out = (const unsigned char*) rtnVal;
            printf("out value:: %s\n",*out);
            *outlen = strlen(rtnVal);
            printf("out len:: %d\n",*outlen);
            break;
        case 2000:
            printf("[mb_c] 2000, ext_add_cb from mb_c!\n");
            rtnVal = "give me warrant";
            *out = (const unsigned char*) rtnVal;
            printf("out value:: %s\n",*out);
            *outlen = strlen(rtnVal);
            printf("out len:: %d\n",*outlen);
            break;
        case 3000:
            printf("[mb_c] 3000, ext_add_cb from mb_c!\n");
            rtnVal = "give me pub key";
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
}


static void ext_free_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *out, void *add_arg)
{
    printf("[mb_c] ext_free_cb from server called \n");
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
{
    printf("[mb_c] ext_parse_cb from server called!\n");
    static const char *in_proxy_del, *in_warrant;
    switch (ext_type) {
        case 1000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive proxy-delegation
            in_proxy_del = in;
            printf("in value size:: %d\n", inlen);
            write_to_file("proxy-delegation.txt", in);
            //gen_proxy_sign_key(in, inlen);
            break;
        case 2000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive warrant
            in_warrant = in;
            printf("in value size:: %d\n", inlen);
            write_to_file("warrant.txt", in);
            break;
        case 3000:
            printf("[ext_type]:: %d\n", ext_type);
            printf("in value:: %s\n", in);  // receive server public key
            printf("in value size:: %d\n", inlen);
            gen_proxy_sign_key(in_proxy_del, in_warrant, in);
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

    int result = SSL_CTX_add_client_custom_ext(ctx, 1000, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);
    int result2 = SSL_CTX_add_client_custom_ext(ctx, 2000, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);
    int result3 = SSL_CTX_add_client_custom_ext(ctx, 3000, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);
    
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);                 /* create new SSL connection state */
    SSL_set_fd(ssl, server);            /* attach the socket descriptor */

    int middlebox = 2;      // client-side middlbox
    SSL_set_ex_data(ssl, 0, &middlebox);

    int *rtn_mb = SSL_get_ex_data(ssl, 0);

    if(rtn_mb == NULL){
        printf("This is not middlebox\n");
    }else{
        printf("is this middlebox?? %d\n", *rtn_mb);
    }

    printf("Set SSL and Socket connection!! \n");

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

        // ath test start
        //const char *cipher_suite = SSL_get_cipher(ssl);
        //printf("Cipher Suite: %s\n", cipher_suite);
        //struct ssl_cipher_st_test  *structPtr = malloc(sizeof(struct ssl_cipher_st_test ));
        //
        //char name[1000];
        //char stdname[1000];
        
        // 파일에서 구조체 읽어오기 (for test)
        //FILE *file3 = fopen("/home/mdtls/cipher.data", "r"); // "rb"는 바이너리 읽기 모드
        //if (file3 != NULL) {
        //    fscanf(file3, "%u", &structPtr->valid);
        //    fscanf(file3, "%s", name);
        //    fscanf(file3, "%s", stdname);
        //    fscanf(file3, "%u", &structPtr->id);
        //    fscanf(file3, "%u", &structPtr->algorithm_mkey);
        //    fscanf(file3, "%u", &structPtr->algorithm_auth);
        //    fscanf(file3, "%u", &structPtr->algorithm_enc);
        //    fscanf(file3, "%u", &structPtr->algorithm_mac);
        //    fscanf(file3, "%d", &structPtr->min_tls);
        //    fscanf(file3, "%d", &structPtr->max_tls);
        //    fscanf(file3, "%d", &structPtr->min_dtls);
        //    fscanf(file3, "%d", &structPtr->max_dtls);
        //    fscanf(file3, "%u", &structPtr->algo_strength);
        //    fscanf(file3, "%u", &structPtr->algorithm2);
        //    fscanf(file3, "%d", &structPtr->strength_bits);
        //    fscanf(file3, "%u", &structPtr->alg_bits);   
        //    fclose(file3);

            // 읽어온 데이터 출력
            //structPtr->name = name;
            //structPtr->stdname = stdname;
            //printf("valid ::: %u\n", structPtr->valid );
            //printf("name ::: %s\n", structPtr->name );
            //printf("stdName ::: %s\n", structPtr->stdname );
            //printf("id ::: %u\n", structPtr->id );
            //printf("algorithm_mkey ::: %u\n", structPtr->algorithm_mkey );
            //printf("algorithm_auth ::: %u\n", structPtr->algorithm_auth );
            //printf("algorithm_enc ::: %u\n", structPtr->algorithm_enc );
            //printf("algorithm_mac ::: %u\n", structPtr->algorithm_mac );
            //printf("min_tls ::: %d\n", structPtr->min_tls );
            //printf("max_tls ::: %d\n", structPtr->max_tls );
            //printf("min_dtls ::: %d\n", structPtr->min_dtls );
            //printf("max_dtls ::: %d\n", structPtr->max_dtls );
            //printf("algo_strength ::: %u\n", structPtr->algo_strength );
            //printf("algorithm2 ::: %u\n", structPtr->algorithm2 );
            //printf("strength_bits ::: %d\n", structPtr->strength_bits );
            //printf("alg_bits ::: %u\n", structPtr->alg_bits );
        //} else {
        //    fprintf(stderr, "Failed to open cipher.data file.\n");
        //}
        // ath test end

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