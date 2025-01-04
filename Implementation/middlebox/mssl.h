#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define DEFAULT_BUF_SIZE 1024
#define MAX_CLNT_SIZE 1000
#define MAX_THREADS 100
/*

#define MAX_CLNT_SIZE 1000


#define DEFAULT_CERT "matls_cert.crt"
#define DEFAULT_PRIV "matls_priv.pem"
#define DEFAULT_CA_PATH "/etc/ssl/certs"
#define DEFAULT_FORWARD_FILE "forward.txt"
*/

#ifdef REF
SSL_CTX *ctx;

// Thread related definitions.
pthread_t threads[MAX_THREADS];
pthread_attr_t attr;
#else
extern SSL_CTX *ctx;
extern pthread_t threads[MAX_THREADS];
extern pthread_attr_t attr;
#endif
struct forward_info
{
  int index;
  SSL *ssl;
};


void *run(void *data);
void sni_callback(unsigned char *buf, int len, SSL *ssl);
int get_thread_index(void);
void init_thread_config(void);