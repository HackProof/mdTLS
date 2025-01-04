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
#include <sys/time.h>
#include "../common.h"


#define FAIL    -1
#define BUF_SIZE 1024
#define h_addr h_addr_list[0] /* for backward compatibility */

#define ECDSA_CLNT_PUB_KEY_PATH "clnt.pub"


const char *hostname, *portnum;
SSL_CTX *ctx;



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
    //SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();                           // Load cryptos, et.al.
    SSL_load_error_strings();                               // Bring in and register error messages
    
    method = TLSv1_2_client_method();                       // Create new client-method instance
    //method = TLS_client_method();                         // Create new client-method instance
    
    ctx = SSL_CTX_new(method);                              // Create new context
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);     // set TLS version
    //printf("TLS version:: %d\n\n", SSL_CTX_get_max_proto_version(ctx));
    
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }

    SSL_CTX_enable_mb(ctx);
    printf("[DEBUG] %s:%s:%d: SSL_CTX_enable_mb\n", __FILE__, __func__, __LINE__);
    return ctx;
}

int open_connection(const char *hostname, int port)
{
    int sd, optval = 1;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL ){
        printf("[ERROR] %s:%s:%d: \n", __FILE__, __func__, __LINE__);
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    //setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){
        //printf("[mdtls] %s:%s:%d: \n", __FILE__, __func__, __LINE__);
        close(sd);
        perror(hostname);
        abort();
    }
    //printf("[mdtls] %s:%s:%d: \n", __FILE__, __func__, __LINE__);
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
    //printf("Server Public key Bits:: %d \n", EVP_PKEY_bits(pubkey));
    
    //EC_KEY *eckey;
    //eckey = EVP_PKEY_get1_EC_KEY(pubkey);
        
    //FILE *f;
    //int result;
    //f = fopen("key.pem", "wb");
    //result = PEM_write_PUBKEY(f, pubkey);
    // Check server's public key in certificate (END)

    if ( cert != NULL ){
        //printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        //printf("Subject: %s\n", line);
        free(line);       // free the malloc'ed string
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        //printf("Issuer: %s\n", line);
        free(line);       // free the malloc'ed string 
        X509_free(cert);     // free the malloc'ed certificate copy
    }
    else{
        //printf("Info: No client certificates configured.\n");
    }
        
}

void *run(void *data)
{
 	printf("[DEBUG] %s:%s:%d: \n", __FILE__, __func__, __LINE__);	
 	int server, sent, rcvd, ret;
   	unsigned char buf[BUF_SIZE];
 	SSL *ssl;
   	const char *request = 
     "GET / HTTP/1.2\r\n"
     "Host: www.mdtls_thyun.com\r\n\r\n";
   	int request_len = strlen(request);
    //printf("[DEBUG] %s:%s:%d: Msg Length: %d\n", __FILE__, __func__, __LINE__, request_len);

    //load_certificates(ctx, cert, key);
    ShowServerCerts(ssl);  
    //printf("[DEBUG] %s:%s:%d: Show Server Certs\n", __FILE__, __func__, __LINE__);
 	
    //printf("[mdtls] %s:%s:%d: #1\n", __FILE__, __func__, __LINE__);	
 	server = open_connection(hostname, atoi(portnum));
    //printf("[DEBUG] %s:%s:%d: Open Connection\n", __FILE__, __func__, __LINE__);

 	ssl = SSL_new(ctx);      /* create new SSL connection state */
    //printf("[DEBUG] %s:%s:%d: ssl pointer :: %p\n", __FILE__, __func__, __LINE__, ssl);

    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    //printf("[mdtls] %s:%s:%d:%s\n", __FILE__, __func__, __LINE__, hostname);
 	SSL_set_tlsext_host_name(ssl, hostname);
 	//ssl->time_log = time_log;
   	//printf("[mdtls] %s:%s:%d: Set server name: %s\n", __FILE__, __func__, __LINE__, hostname);
    
    //struct timeval tv;
    //gettimeofday( &tv, 0 );
 	
    //printf("PROGRESS: TLS Handshake Start!\n");
    unsigned long hs_start, hs_end, rec_start, rec_end;
 	hs_start = get_current_microseconds();
    //printf("[TIME] %s:%s:%d: HS CLIENT START: %lu µs\n", __FILE__, __func__, __LINE__, hs_start);
 	//RECORD_LOG(ssl->time_log, CLIENT_HANDSHAKE_START);
   if ( (ret = SSL_connect(ssl)) < 0 ){   //perform the connection
        //printf("ret after SSL_connect: %d\n", ret);
        ERR_print_errors_fp(stderr);
   }else{
 		//RECORD_LOG(ssl->time_log, CLIENT_HANDSHAKE_END);
 		//INTERVAL(ssl->time_log, CLIENT_HANDSHAKE_START, CLIENT_HANDSHAKE_END);
 		hs_end = get_current_microseconds();
        //printf("[TIME] %s:%s:%d: HS CLIENT END: %lu µs\n", __FILE__, __func__, __LINE__, hs_end);
        printf("[TIME] %s:%s:%d: TOTAL ELAPSED HS TIME: %lu µs\n", __FILE__, __func__, __LINE__, hs_end - hs_start);

        rec_start = get_current_microseconds();
 		sent = SSL_write(ssl, request, request_len);
 		//MA_LOG1s("Request", request);
        printf("[DEBUG] %s:%s:%d: Client Request Msg: %s\n", __FILE__, __func__, __LINE__, request);
 		
        rcvd = SSL_read(ssl, buf, BUF_SIZE);
        rec_end = get_current_microseconds();
        printf("[TIME] %s:%s:%d: TOTAL ELAPSED REC TIME: %lu µs\n", __FILE__, __func__, __LINE__, rec_end - rec_start);
 		
 		buf[rcvd] = 0;
 		//MA_LOG1s("Response", buf);
 		//MA_LOG1d("Rcvd Length", rcvd);
        printf("[DEBUG] %s:%s:%d: Client Received Msg: %s\n", __FILE__, __func__, __LINE__, buf);
 	}
      
 	SSL_free(ssl);        /* release connection state */
     
 	close(server);         /* close socket */
}


int main(int count, char *strings[])
{
    if ( count != 3 ){
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    
    int rc, numOfThreads = 1;
    void *status;
    //SSL_CTX *ctx;

    pthread_t thread[numOfThreads];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();

    for (int i=0; i<numOfThreads; i++){
		rc = pthread_create(&thread[i], &attr, run, NULL);
		if (rc){
			printf("ERROR: return code from pthread_create: %d\n", rc);
			return 1;
		}
	}

	pthread_attr_destroy(&attr);

	for (int i=0; i<numOfThreads; i++){
		rc = pthread_join(thread[i], &status);

		if (rc){
			printf("ERROR: return code from pthread_join: %d\n", rc);
			return 1;
		}
	}

    SSL_CTX_free(ctx);        /* release context */

    return 0;  