#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "../common.h"

#define FAIL    -1
#define CHAR_LENGTH    2048

#define ECDSA_PUB_KEY_PATH "clnt-side/mb_c.pub"
#define ECDSA_CERT_FILE_PATH    "../server/cert/server.cer"
#define SRVR_PUB_KEY_PATH    "srvr.pub"

//#define SRVR_CERT_PATH "../server/cert/server.cer"
//#define ECDSA_PRIVATE_KEY_PATH  "../server/cert/combined.pri"
//#define ECDSA_PRIVATE_KEY_PATH  "cert/ec.pri"
//#define ECDSA_CERT_FILE_PATH    "cert/serverCert.pem"
//#define SERVER_PUBLIC_KEY_PATH  "certs/serverPk.pem"
//#define MB_C_PUBLIC_KEY_PATH    "extensions/mb_c_ecdsa.pub"

EVP_PKEY *serverPk;

uint8_t* ProxyDelegation();
/****************************************************************************
                            *   Callback functions   * 
 ****************************************************************************/


/****************************************************************************
                            *   User-defined functions   * 
 ****************************************************************************/

int isRoot()
{
    if (getuid() != 0){
        return 0;
    }else{
        return 1;
    }
}

SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();   // load & register all cryptos, etc.
    SSL_load_error_strings();       // load all error messages

    //method = TLS_server_method();
    method = TLSv1_2_server_method();  // create new server-method instance (deprecated)
    ctx = SSL_CTX_new(method);      // create a new SSL_CTX object as framework for TLS/SSL or DTLS enabled functions (by thyun.ahn)
                                    // create new context from method 
                                    // initialize the list of cipher suites, the session of cache setting, the callbacks, the keys and certificates ... (by thyun.ahn)
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");

    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    // set the local certificate from CertFile
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ){
        ERR_print_errors_fp(stderr);
        abort();
    }
    // set the private key from KeyFile (may be the same as CertFile)
    // if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ){
    //     ERR_print_errors_fp(stderr);
    //     abort();
    // }
    // verify private key
    // if ( !SSL_CTX_check_private_key(ctx) ){
    //     fprintf(stderr, "Private key does not match the public certificate\n");
    //     abort();
    // }
}

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);   // 서버 socket 생성
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){  // 서버 주소와 socket bind    
        perror("can't bind port");
        abort();
    }

    if ( listen(sd, 10) != 0 ){
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

//void ShowClientCerts(SSL* ssl)
//{
//    X509 *cert;
//    char *line;
//    cert = SSL_get_peer_certificate(ssl); // Get certificates (if available)
//    if ( cert != NULL ){
//        printf("Server certificates:\n");
//        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
//        printf("Subject: %s\n", line);
//        free(line);
//        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
//        printf("Issuer: %s\n", line);
//        free(line);
//        X509_free(cert);
//    } else
//        printf("No certificates.\n");
//}

void Servlet(SSL* ssl) //Serve the connection -- threadable
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse=
    " <Body>\
        <Name>aticleworld.com</Name>\
        <year>1.5</year>\
        <BlogType>Embedded and c<\\BlogType>\
        <Author>amlendra<Author>\
    <\\Body>";

    //char *serverResponse = sign();
    //printf("base64 returned signature:: %s\n", serverResponse);

    //verify(serverResponse);

    const char *cpValidMessage = 
    "<Body>\
        <UserName>aticle<UserName>\
        <Password>123<Password>\
    <\\Body>";
    printf("before SSL_accept!!!! \n");

    // middlebox flag
    int middlebox = 3;  // server-side middlbox
    SSL_set_ex_data(ssl, 1, &middlebox);

    // middlebox cert load
    
    //int *rtn_mb = SSL_get_ex_data(ssl, 0);
    //printf("middlebox?? %d\n", *rtn_mb);

    if ( SSL_accept(ssl) == FAIL ){     // 클라이언트와의 초기 협상과정, 즉 핸드쉐이크 과정을 수행(가장 중요한 함수)
        ERR_print_errors_fp(stderr);
        printf("SSL_accept error:: \n");
    }else{
        printf("SSL_accept!! :: \n");
        
        const char *cipher_suite = SSL_get_cipher(ssl);
        printf("Cipher Suite: %s\n", cipher_suite);
        
        //ShowClientCerts(ssl);                       // get any certificates
        bytes = SSL_read(ssl, buf, sizeof(buf));    // get request
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        if ( bytes > 0 ){
            printf("debug: %d \n", strcmp(cpValidMessage,buf));
            if(strcmp(cpValidMessage,buf) == 0){
                SSL_write(ssl, ServerResponse, strlen(ServerResponse));     // send reply signature
                //SSL_write(ssl, cpValidMessage, strlen(cpValidMessage));     // send reply 
            }else{
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); // send reply
            }
        }else {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);   // get socket connection
    SSL_free(ssl);          // release SSL state
    close(sd);              // close connection
}


/****************************************************************************
                            *   Callback functions   * 
 ****************************************************************************/

static int ext_add_cb(SSL *s, unsigned int ext_type,
                      const unsigned char **out,
                      size_t *outlen, int *al, void *add_arg)
{
    switch (ext_type) {
        case 1000:
        {
           printf("1000,  [Server] ext_add_cb\n");
           char *rtn = read_from_file("proxy-delegation.txt");
           *out =(const unsigned char*) rtn;
           printf("out :: signed_delegation:: %s\n", *out);            
           *outlen = strlen(rtn)+1;
           printf("len:: %d", *outlen);
           break;
        }
        case 2000:
        {
           printf("2000,  [Server] ext_add_cb\n");
           char *rtn = read_from_file("warrant.txt");
           *out = (const unsigned char*) rtn;
           printf("out #2:: warrant:: %s\n", *out);            
           *outlen = strlen(*out)+1;
           printf("len:: %d", *outlen);
           break;
        }
        case 3000:
        {
            printf("3000,  [mb_s] ext_add_cb\n");
            *out =  read_from_file(SRVR_PUB_KEY_PATH);
            printf("out #3:: server public key:: %s\n", *out);            
            *outlen = strlen(*out)+1;
            printf("len:: %d", *outlen);
            break;
        }
        case 4000:
        {
            printf("3000,  [mb_s] ext_add_cb\n");
            *out =  read_from_file(ECDSA_PUB_KEY_PATH);
            printf("out #3:: mb_s public key:: %s\n", *out);            
            *outlen = strlen(*out)+1;
            printf("len:: %d", *outlen);
            break;
        }
        default:
            printf("[Server] Default\n");
            break;
    }
     
    //switch (ext_type) {
    //    case 1000:
    //    {
    //        printf("1000,  [Server] ext_add_cb\n");
    //        //*out = (const unsigned char*)proxyDelegation();
    //        printf("out message:: \n");
    //                   
    //        //*out = (const unsigned char*) encodeTemp.c_str();            
    //        const char *rtnVal;
    //        rtnVal="server message";
    //        *out = rtnVal;            
    //        *outlen = strlen(rtnVal);
    //        printf("len:: %d", *outlen);
    //        break;
    //    }
    //    default:
    //        printf("[Server] Default\n");
    //        break;
    //}
    return 1;
}

static void ext_free_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *out, void *add_arg)
{
    printf("[mb_s] ext_free_cb\n");
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)     // parse_arg는 extension 함수 호출 시 설정한 값
{
    printf("[mb_s] ext_parse_cb from middlebox!\n");
    
    switch (ext_type) {
        //case 1000:
        //    printf("mb_s received client's public key for proxy signature\n");    
        //    printf("in value:: %s\n", in);
        //    write_to_file(ECDSA_MB_PUBKEY_PATH, in);
        //    delegate_proxy_signer();
        //    break;
        //case 2000:
        //    printf("[ext_type]:: %d", ext_type);
        //    printf("in value:: %s\n", in); 
        //    printf("in value size:: %d\n", inlen);
        //    break;
        case 3000:
            printf("[ext_type]:: %d", ext_type);
            printf("in value:: %s\n", in); 
            printf("in value size:: %d\n", inlen);
            break;    
    }

    return 1;
}


int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;
    char *srvr_cert_path = ECDSA_CERT_FILE_PATH; //SRVR_CERT_PATH;
    
    //Only root user have the permsion to run the server
    if(!isRoot()){
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 ){
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    
    ctx = InitServerCTX();        // initialize SSL

    server = OpenListener(atoi(portnum));   // create server socket

    // LoadCertificates(ctx, "mycert.pem", "mycert.pem");        // load certs
    LoadCertificates(ctx, srvr_cert_path, NULL);    // load certs
    
    // get public key from certificate
    serverPk = GetPublickeyFromCert(srvr_cert_path);
    
    while (1){
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        // accept 함수를 실행 하여 클라이언트로부터의 접속 기다림
        int client = accept(server, (struct sockaddr*)&addr, &len);

        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        int result = SSL_CTX_add_server_custom_ext(ctx, 3000, ext_add_cb, ext_free_cb, NULL, ext_parse_cb, NULL);

        ssl = SSL_new(ctx);           // get new SSL state with context
        SSL_set_fd(ssl, client);      // socket과 SSL 연결

        int middlebox = 3;      // server-side middlbox
        SSL_set_ex_data(ssl, 1, &middlebox);
        

        Servlet(ssl);           // service connection
    }
    close(server);              // close server socket
    SSL_CTX_free(ctx);          // release context
}


/*
char* sign()
{
    char *concatText="hello";

    // ECDSA sign
    FILE * f = fopen(ECDSA_PRIVATE_KEY_PATH, "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f,NULL,NULL,NULL);
    fclose(f);
    
    EVP_PKEY *key = EVP_PKEY_new();
    int assignEcKeyResult = EVP_PKEY_assign_EC_KEY(key, ec_key);
    printf("check assign EC key:: %d\n", assignEcKeyResult);

    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_new();

    if ( EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key) <= 0 ){
        printf("*** EVP_DigestSignInit fail!!!\n");
        return "";
    }

    if ( EVP_DigestSignUpdate(md_ctx, concatText, strlen(concatText)) <= 0 ){
        printf("*** EVP_DigestSignUpdate fail!!!\n");
        return "";
    }

    unsigned char *sign = NULL;
    size_t signlen = 0;

    if (!EVP_DigestSignFinal(md_ctx, NULL, &signlen)) {
        printf("*** EVP_Digest sign final fail!!!!!\n");
        return "";
    }
    
    sign = (unsigned char *)malloc(signlen);

    int signResult = EVP_DigestSignFinal(md_ctx, sign, &signlen);
    if ( signResult <= 0 ){
        printf("*** EVP_DigestSignFinal fail!!!\n");
        return "";
    }
    
    printf("=========sign==========\n");
    for (size_t i = 0; i < signlen; i++) {
        printf("%02x", sign[i]);
    }
    printf("\n");

    printf("EVP_DIGEST SIGN RESULT:: %d\n", signResult);
    printf("signLen with value:: %d\n", signlen);
    printf("signature:: %s\n", sign);

    char *base64Sign;
    Base64Encode(sign, signlen, &base64Sign);
    printf("encoded signature:: %s\n", base64Sign);
    
    return base64Sign;
}
*/
/*
void verify(const char *base64Sign)
{
    char *concatText = "hello";

    X509 *x509_cert;  // X.509 인증서를 나타내는 구조체
    EVP_PKEY *evp_key;  // OpenSSL 공개 키 구조체

    // X.509 인증서로부터 공개 키 추출
    evp_key = GetPublickeyFromCert(ECDSA_CERT_FILE_PATH);

    // start verification
    EVP_MD_CTX *md_ctx_verify = EVP_MD_CTX_new();

    if ( EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sha256(), NULL, evp_key) <= 0 ){
        printf("EVP_DigestVerifyInit\n");
        return;
    }

    if ( EVP_DigestVerifyUpdate(md_ctx_verify, concatText, strlen(concatText)) <= 0 ){
        printf("EVP_DigestVerifyUpdate\n");
        return;
    }
    printf("verification update\n");

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

    int verifyResult = EVP_DigestVerifyFinal(md_ctx_verify, decodedSign, decodedSignLen);  //signlen
    if ( verifyResult <= 0 ){
        printf("EVP_DigestVerifyFinal failed....\n");
        printf("EVP_DIGEST VERIFY RESULT:: %d\n", verifyResult);
        return;
    }
    printf("verification final\n");
    printf("EVP_DIGEST VERIFY RESULT:: %d\n", verifyResult);

    // 메모리 해제
    EVP_PKEY_free(evp_key);
    EVP_MD_CTX_free(md_ctx_verify);
    X509_free(x509_cert);
}
*/