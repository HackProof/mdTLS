#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include <sys/time.h>
#include "../common.h"

#define REF_TABLE
#include "table.h"
#define REF
#include "mssl.h"

#define h_addr h_addr_list[0] /* for backward compatibility */

#define FAIL    -1
#define BUF_SIZE 1024
#define CHAR_LENGTH    2048
#define ECDSA_PUB_KEY_PATH      "key_cert/ecdsa.pub"
#define ECDSA_CERT_FILE_PATH    "../server/cert/server.cer"
#define SRVR_PUB_KEY_PATH       "srvr.pub"

#define DHFILE  "../matls_include/dh1024.pem"

//#define SRVR_CERT_PATH "../server/cert/server.cer"
//#define ECDSA_PRIVATE_KEY_PATH  "../server/cert/combined.pri"
//#define ECDSA_PRIVATE_KEY_PATH  "cert/ec.pri"
//#define ECDSA_CERT_FILE_PATH    "cert/serverCert.pem"
//#define SERVER_PUBLIC_KEY_PATH  "certs/serverPk.pem"
//#define MB_C_PUBLIC_KEY_PATH    "extensions/mb_c_ecdsa.pub"

EVP_PKEY *serverPk;
int modification;

struct info
{
  int sock;
};

//uint8_t* ProxyDelegation();
/****************************************************************************
                            *   Callback functions   * 
 ****************************************************************************/


/****************************************************************************
                            *   User-defined functions   * 
 ****************************************************************************/




SSL_CTX* init_middlebox_ctx(int server_side)
{
	  SSL_METHOD *method;

    SSL_load_error_strings();   /* load all error messages */
    method = (SSL_METHOD *) TLSv1_2_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL ){
      printf("[ERROR] SSL_CTX init failed!");
      abort();
    }
    
    SSL_CTX_set_sni_callback(ctx, sni_callback);
    SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-SHA256");
  
    SSL_CTX_is_middlebox(ctx);

    if (server_side){
        SSL_CTX_set_server_side(ctx);
        //SSL_CTX_use_proof_file(ctx, proof_file);
    }else
        SSL_CTX_set_client_side(ctx);

    SSL_CTX_enable_mb(ctx);
	
    
    return ctx;
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret=0;
  BIO *bio;

  if ((bio=BIO_new_file(file,"r")) == NULL){
    perror("Couldn't open DH file");
  }

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if(SSL_CTX_set_tmp_dh(ctx,ret) < 0){ 
    perror("Couldn't set DH parameters");
  }
}




void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
        #ifdef DEBUG
            printf("SSL_CTX_load_verify_locations success\n");
        #endif /* DEBUG */
  }

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
        #ifdef DEBUG
            printf("SSL_CTX_set_default_verify_paths success\n");
        #endif /* DEBUG */
  }
  //printf("[DEBUG] %s:%s:%d:%s \n", __FILE__, __func__, __LINE__, cert_file);
	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
        #ifdef DEBUG
            printf("SSL_CTX_use_certificate_file success\n");
        #endif /* DEBUG */
  }
  
  /** register_id 주석처리 (안태현)*/
  //if ( SSL_CTX_register_id(ctx) <= 0 ){
  //  printf("[mdtls] %s:%s:%d: SSL_CTX_register_id failed \n", __FILE__, __func__, __LINE__);  
  //  abort();
  //}else{
  //    //#ifdef DEBUG
  //        printf("[mdtls] %s:%s:%d: SSL_CTX_register_id success \n", __FILE__, __func__, __LINE__);
  //    //#endif /* DEBUG */
  //}

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
        #ifdef DEBUG
            printf("SSL_CTX_use_PrivateKey_file success\n");
        #endif /* DEBUG */
  }

	/* Verify private key */
	if ( !SSL_CTX_check_private_key(ctx) ){
		ERR_print_errors_fp(stderr);
		abort();
	}else{
        #ifdef DEBUG
            printf("SSL_CTX_check_private_key success\n");
        #endif /* DEBUG */
  }

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}

int open_listener(int port)
{
    int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ){
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, MAX_CLNT_SIZE) != 0 ){
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}


int get_total_length(char *buf, int rcvd)
{
  int tot_len, head_len, body_len, index, tok_len, mrlen, len;
  const char *clen = "Content-Length";
  char *token = NULL;
  char val[4];

  head_len = strstr(buf, "\r\n\r\n") - buf + 4;
  //MA_LOG1d("Header Length", head_len);
  
  token = strtok(buf, "\n");

  while (token){
    tok_len = strlen(token);
    index = strstr(token, ":") - token;

    if (strncmp(token, clen, index - 1) == 0){
      memcpy(val, token + index + 1, tok_len - index - 1);
      body_len = atoi(val);
      //MA_LOG1d("Body Length", body_len);
      break;
    }
    token = strtok(NULL, "\n");
  }

  tot_len = head_len + body_len;

  return tot_len;
}

void *mb_run(void *data)
{
  printf("[DEBUG] %s:%s:%d:: is mb_run Execute??\n", __FILE__, __func__, __LINE__);
  struct info *info;
  int client, ret, rcvd, sent, fd, tot_len = -1, head_len = -1, body_len = -1;
  unsigned char buf[BUF_SIZE];
  unsigned long start, end;

  char modified[134] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 70\r\n"
    "\r\n"
    "<html><title>Test</title><body><h1>Test Bob's Page!</h1></body></html>";
  int modified_len = strlen(modified);

  SSL *ssl;

  info = (struct info *)data;
  client = info->sock;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client);

//#ifdef MATLS
  //printf("[thyun][smb.c > mb_run()] before ssl_enable_mb()\n");
  SSL_enable_mb(ssl);
//#else
//  SSL_disable_mb(ssl);
//  MA_LOG("split tls enabled");
//#endif

  //start = get_current_microseconds();
  //MA_LOG("before ssl accept");
  printf("[DEBUG] %s:%s:%d: Before SSL accept\n", __FILE__, __func__, __LINE__);
  ret = SSL_accept(ssl);
  printf("[DEBUG] %s:%s:%d: After SSL accept\n", __FILE__, __func__, __LINE__);
  
  unsigned long hs_clnt_end;
 	hs_clnt_end = get_current_microseconds();
  printf("[mdtls] %s:%s:%d: HS CLIENT END: %lu µs\n", __FILE__, __func__, __LINE__, hs_clnt_end);

  if (SSL_is_init_finished(ssl)){
      printf("[DEBUG] %s:%s:%d: Handshake Completed\n", __FILE__, __func__, __LINE__);
  }
  
  printf("[DEBUG] %s:%s:%d: DEBUGGING the value? :: %d\n", __FILE__, __func__, __LINE__, SSL_get_pair(ssl)==NULL);
  
  int chk_loop_cnt_pair = 0;
  while(SSL_get_pair(ssl)==NULL){
    printf("[DEBUG] %s:%s:%d: Check Loop\n", __FILE__, __func__, __LINE__);
    chk_loop_cnt_pair++;
  }
  printf("[DEBUG] %s:%s:%d:: chk_loop_cnt_pair :: %d \n", __FILE__, __func__, __LINE__, chk_loop_cnt_pair);

  //while(SSL_get_pair(ssl)==NULL || !(SSL_get_pair(ssl) && SSL_is_init_finished(ssl) && SSL_is_init_finished(SSL_get_pair(ssl)))) {} // while (thyun.ahn)

  //if (!SSL_is_init_finished(SSL_get_pair(ssl))){
  //  printf("[ERROR] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
  //}

  //MA_LOG1d("end matls handshake", ret);
  //MA_LOG1p("ssl->pair", ssl->pair);
  //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);

  //printf("[DEBUG] %s:%s:%d:%d SSL_is_init_finished(ssl)\n", __FILE__, __func__, __LINE__, SSL_is_init_finished(ssl));
  //printf("[DEBUG] %s:%s:%d:%d SSL_is_init_finished(ssl->pair)\n", __FILE__, __func__, __LINE__, SSL_is_init_finished(SSL_get_pair(ssl)));
  
  //while (!(SSL_get_pair(ssl) && SSL_is_init_finished(ssl) && SSL_is_init_finished(SSL_get_pair(ssl)))) {}
  //while (SSL_get_pair(ssl)==NULL) {}
  
  printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
  
  while (1){
    rcvd = SSL_read(ssl, buf, BUF_SIZE);
    //MA_LOG1d("Received from Client-side", rcvd);
    //MA_LOG1s("Message from Client-side", buf);
    printf("[DEBUG] %s:%s:%d: rcvd: %d\n", __FILE__, __func__, __LINE__, rcvd);
    printf("[mdtls] %s:%s:%d: Msg from Client: %s\n", __FILE__, __func__, __LINE__, buf);

    printf("[DEBUG] %s:%s:%d: #2 ssl pointer %p\n", __FILE__, __func__, __LINE__, ssl);
    printf("[DEBUG] %s:%s:%d: #2 ssl pair pointer (server) %p\n", __FILE__, __func__, __LINE__, SSL_get_pair(ssl));
    printf("[mdtls] %s:%s:%d: Deliver Client's Msg to Server: %s\n", __FILE__, __func__, __LINE__, buf);
    sent = SSL_write(SSL_get_pair(ssl), buf, rcvd);
    //MA_LOG1d("Sent to Server-side", sent);
    printf("[DEBUG] %s:%s:%d: Sent to Server: %d\n", __FILE__, __func__, __LINE__, sent);

    do {
      rcvd = SSL_read(SSL_get_pair(ssl), buf, BUF_SIZE);
      //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);  
      //MA_LOG1d("Received from Server-side", rcvd);
      //MA_LOG1s("Message", buf);
      
      if (modification)
        sent = SSL_write(ssl, modified, modified_len);
      else
        sent = SSL_write(ssl, buf, rcvd);

      //MA_LOG1d("Sent to Client-side", sent);

      if (tot_len < 0){
        if (modification)
          tot_len = get_total_length((char *)modified, modified_len);
        else
          tot_len = get_total_length(buf, rcvd);
      }

      //MA_LOG1d("Total Length", tot_len);

      tot_len -= rcvd;

      if (tot_len <= 0)
        break;
    } while(1);

    break;
  }
  //end = get_current_microseconds();
  //MA_LOG1lu("Middlebox Execution Time", end - start);

  fd = SSL_get_fd(SSL_get_pair(ssl));
  SSL_free(SSL_get_pair(ssl));
  SSL_free(ssl);
  close(fd);
  close(client);
}

int main(int count, char *strings[])
{   
	int server, client, rc, tidx = 0, i, server_side;
	char *portnum, *cert, *key, *forward_file;
  void *status;

	if ( count != 7 ){
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];    //ECDSA_CERT_FILE_PATH;    //strings[2];
	key = strings[3];     //ECDSA_PUB_KEY_PATH;       //strings[3];
  forward_file = strings[4];
  server_side = atoi(strings[5]);
  modification = atoi(strings[6]);
  //proof_file = strings[7];

  ctx = init_middlebox_ctx(server_side);        //initialize SSL
    
  load_dh_params(ctx, DHFILE);
  load_certificates(ctx, cert, key);

  init_forward_table(forward_file);
  
  init_thread_config();

	server = open_listener(atoi(portnum));    // create server socket

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
    
	while (1) {
    client = accept(server, (struct sockaddr *)&addr, &len);

    if (client < 0){
        printf("error in accept\n");
        exit(EXIT_FAILURE);
    }

    struct info *info = (struct info *)malloc(sizeof(struct info));
    info->sock = client;
    tidx = get_thread_index();
    rc = pthread_create(&threads[tidx], &attr, mb_run, info);

    if (rc < 0){
        //MA_LOG("error in pthread create");
        exit(EXIT_FAILURE);
    }

    pthread_attr_destroy(&attr);

    rc = pthread_join(threads[tidx], &status);

    if (rc){
        //MA_LOG1d("error in join", rc);
        return 1;
    }
	}

  free_forward_table();
	SSL_CTX_free(ctx);         // release context 
	close(server);          // close server socket
  

	return 0;
}