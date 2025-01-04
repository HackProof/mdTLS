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
#include "../module/proxy.h"

#define FAIL    -1
#define CHAR_LENGTH    2048

#define DHFILE  "../matls_include/dh1024.pem"

#define ECDSA_PRIVATE_KEY_PATH  "cert/ec.pri"
#define ECDSA_PUBLIC_KEY_PATH   "cert/ec.pub"
#define ECDSA_CERT_FILE_PATH    "cert/server.cer"
#define WARRANT_PATH            "cert/warrant.txt"
#define ECDSA_MB_PUBKEY_PATH    "others/mb.pub"

//#define SERVER_PUBLIC_KEY_PATH  "certs/serverPk.pem"
//#define MB_C_PUBLIC_KEY_PATH    "extensions/mb_c_ecdsa.pub"

EVP_PKEY *serverPk;
const char* signed_delegation;
int running = 1;
char *fname = NULL;
FILE *fp = NULL;

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
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();   // load & register all cryptos, etc.
    SSL_load_error_strings();       // load all error messages

    //method = TLS_server_method();
    method = TLSv1_2_server_method();  // create new server-method instance (deprecated)
    ctx = SSL_CTX_new(method);      // create a new SSL_CTX object as framework for TLS/SSL or DTLS enabled functions (by thyun.ahn)
                                    // create new context from method 
                                    // initialize the list of cipher suites, the session of cache setting, the callbacks, the keys and certificates ... (by thyun.ahn)
    if ( ctx == NULL ){
        ERR_print_errors_fp(stderr);
        abort();
    }    
    
    //SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256");
    SSL_CTX_set_cipher_list(ctx,  "DHE-RSA-AES256-SHA256");

    
    SSL_CTX_enable_mb(ctx);
    return ctx;
}



// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);   
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){  
        perror("can't bind port");
        abort();
    }

    if ( listen(sd, 10) != 0 ){
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else{
        //printf("SSL_CTX_load_verify_locations success\n");
    }
		

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else{
        //printf("SSL_CTX_set_default_verify_paths success\n");
    }
		

	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
        //printf("[DEBUG] %s:%s:%d: SSL_CTX_use_certificate_file success \n", __FILE__, __func__, __LINE__);
    }

     
  /* Set the identifier. That is, the hash value of the public key */
    //if (ctx->mb_enabled == 1){
    if (SSL_CTX_get_mb_enabled(ctx) == 1){
         /** register_id 주석처리 (안태현)*/
        //if (SSL_CTX_register_id(ctx) <= 0){
        //    abort();
        //}else{
        //    printf("[DEBUG] %s:%s:%d: SSL_CTX_register_id success \n", __FILE__, __func__, __LINE__);
        //}
        //printf("[DEBUG] %s:%s:%d: mb_enabled \n", __FILE__, __func__, __LINE__);
    }

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
	    //printf("SSL_CTX_use_PrivateKey_file success\n");
    }

	/* Verify private key */
	if (!SSL_CTX_check_private_key(ctx)){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
		//printf("SSL_CTX_check_private_key success\n");
    }

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}




void int_handler(int dummy)
{
  if (fp)
    fclose(fp);
  //MA_LOG("Server is ending");
  running = 0;
  exit(0);
}

// Load parameters from "dh1024.pem"
void load_dh_params(SSL_CTX *ctx, char *file){
  DH *ret=0;
  BIO *bio;

  if ((bio=BIO_new_file(file,"r")) == NULL)
  {
    perror("Couldn't open DH file");
  }

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if(SSL_CTX_set_tmp_dh(ctx,ret) < 0)
  {
    perror("Couldn't set DH parameters");
  }
}

int main(int count, char *strings[])
{
    //Only root user have the permsion to run the server
    if(!isRoot()){
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    
    if ( count != 4 ){
        printf("Usage: %s <portnum> <cert> <key> \n", strings[0]);
        exit(0);
    }
    
    SSL_CTX *ctx;
    int server, sent=0, rcvd=0;
    char *portnum, *cert, *key, *certPath = ECDSA_CERT_FILE_PATH;

    const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 72\r\n"
		"\r\n"
		"<html><title>Test</title><body><h1>This is mdtls Server Page!</h1>\r\n"
        "<p>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</p>\r\n"
        "</body></html>";
	
    int response_len = strlen(response);

    signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];
	key = strings[3];

    //if (count == 5){
    //    fname = strings[4];
    //    fp = fopen(fname, "w");
    //}    
    
    // Initialize the SSL library
    SSL_library_init();
    
    ctx = InitServerCTX();        // initialize SSL
    load_dh_params(ctx, DHFILE);
    load_certificates(ctx, cert, key);

    server = OpenListener(atoi(portnum));   // create server socket
    
    // get public key from certificate
    //serverPk = GetPublickeyFromCert(certPath);

    struct sockaddr_in addr;
    unsigned char buf[2048];
    socklen_t len = sizeof(addr);
    SSL *ssl;
    
    while (1){
        // accept 함수를 실행 하여 클라이언트로부터의 접속 기다림
        int client = accept(server, (struct sockaddr*)&addr, &len);
        //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);

        if(client > 0){
            //printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            ssl = SSL_new(ctx);           // get new SSL state with context
            SSL_set_fd(ssl, client);      // socket과 SSL 연결
            //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
            //Servlet(ssl);           // service connection

            printf("[DEBUG] %s:%s:%d: ssl pointer :: %p\n", __FILE__, __func__, __LINE__, ssl);

            if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
                ERR_print_errors_fp(stderr);

            printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
            
            rcvd = SSL_read(ssl, buf, sizeof(buf));
            printf("[mdtls] %s:%s:%d: Msg from Middlebox: %s\n", __FILE__, __func__, __LINE__, buf);
            
            sent = SSL_write(ssl, response, response_len);

            close(client);
            SSL_free(ssl);
        }
        
    }
    close(server);              // close server socket
    SSL_CTX_free(ctx);          // release context

    return 0;
}