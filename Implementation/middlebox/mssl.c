#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/time.h>

#include "mssl.h"
#define REF
#include "table.h"
#define h_addr h_addr_list[0] /* for backward compatibility */
//#include "common.h"


void sni_callback(unsigned char *buf, int len, SSL *ssl)
{
  printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
  int index, ilen, port, rc, tidx;
  unsigned char *ip; 
  void *status;
  struct forward_info *args;
  
  //printf("server name: %s\n", buf);
  index = find_by_name(buf, len);
  ip = get_ip_by_index(index);
  port = get_port_by_index(index);

  args = (struct forward_info *)malloc(sizeof(struct forward_info));
  args->index = index;
  args->ssl = ssl;

  tidx = get_thread_index();
  //printf("[DEBUG] %s:%s:%d: thread idx: %d\n", __FILE__, __func__, __LINE__, tidx);
  rc = pthread_create(&threads[tidx], &attr, run, args);

  if (rc < 0){
    //MA_LOG("error in pthread create");
    exit(EXIT_FAILURE);
  }
}

int open_connection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    //MA_LOG1s("hostname", hostname);
            
    if ( (host = gethostbyname(hostname)) == NULL )
    {
          perror(hostname);
          abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);

    /////
#ifdef NO_NAGLE
    int flag = 1;
    setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif /* NO_NAGLE */
    /////

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
    return sd;
}


void *run(void *data)
{
  printf("[DEBUG] %s:%s:%d:: is run Execute??\n", __FILE__, __func__, __LINE__);
  struct forward_info *args;
  //struct timeval tv;
  unsigned char *ip;
  unsigned char buf[DEFAULT_BUF_SIZE];
  unsigned char *server_name;  
  int server, port, ret, rcvd, sent;
  SSL *ssl, *pair;

  //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
  args = (struct forward_info *)data;
  //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);
  ip = get_ip_by_index(args->index);
  port = get_port_by_index(args->index);
  server_name = get_name_by_index(args->index);

  //printf("[DEBUG] %s:%s:%d: IP:: %s\n", __FILE__, __func__, __LINE__, ip);
  //printf("[DEBUG] %s:%s:%d: PORT:: %d\n", __FILE__, __func__, __LINE__, port);

  server = open_connection(ip, port);
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, server);
  SSL_set_tlsext_host_name(ssl, server_name);

   //SSL_set_pair(ssl, args->ssl); // 주석처리. 함수의 내부 로직 꺼내서 옮김. 안태현.
  SSL_set_pair(ssl, args->ssl);     //ssl->pair = args->ssl;
  SSL_set_pair(args->ssl, ssl);     //args->ssl->pair = ssl;
  printf("[INFO] %s:%s:%d: #1 ssl pointer %p\n", __FILE__, __func__, __LINE__, ssl);
  printf("[INFO] %s:%s:%d: #1 ssl pair pointer (server) %p\n", __FILE__, __func__, __LINE__, SSL_get_pair(ssl));
  
  SSL_set_mb_info(ssl, args->ssl);  //ssl->mb_info = args->ssl->mb_info;
  
  SSL_set_proxy_info(ssl, args->ssl);  //ssl->proxy_info = args->ssl->proxy_info;

  SSL_set_mtxp(ssl, SSL_get_mtx(ssl));        //args->ssl->lockp = ssl->lockp = &(ssl->lock);
  SSL_set_mtxp(args->ssl, SSL_get_mtx(ssl));
  
  SSL_set_middlebox(ssl, 1);
  SSL_set_middlebox(args->ssl, 1);  //args->ssl->middlebox = ssl->middlebox = 1;

  SSL_set_server_side(ssl, 1);
  SSL_set_server_side(args->ssl, 1);  //args->ssl->server_side = ssl->server_side;
  //printf("[DEBUG] %s:%s:%d:\n", __FILE__, __func__, __LINE__);

  SSL_enable_mb(ssl);

  //printf("[DEBUG] %s:%s:%d: Before SSL connect\n", __FILE__, __func__, __LINE__);
  //unsigned long hs_mb_start, hs_mb_end;
 	//hs_mb_start = get_current_microseconds();
  //printf("[TIME] %s:%s:%d: HS MB START: %lu µs\n", __FILE__, __func__, __LINE__, hs_mb_start);
  
  ret = SSL_connect(ssl);

  //hs_mb_end = get_current_microseconds();
  //printf("[TIME] %s:%s:%d: HS MB END: %lu µs\n", __FILE__, __func__, __LINE__, hs_mb_end);
  //printf("[TIME] %s:%s:%d: MB->SERVER ELAPSED HS TIME: %lu µs\n", __FILE__, __func__, __LINE__, hs_mb_end - hs_mb_start);
  //printf("[DEBUG] %s:%s:%d: After SSL connect\n", __FILE__, __func__, __LINE__);

  if (ret != 1){
    ERR_print_errors_fp(stderr);   
  }else{
    //end = get_current_microseconds();
    printf("[DEBUG] %s:%s:%d: Succeed to connect to %s:%d\n", __FILE__, __func__, __LINE__, ip, port);
  }
}

void init_thread_config(void)
{
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++){
    if (!threads[i]){
      ret = i;
      break;
    }
  }
  //printf("[DEBUG] %s:%s:%d: ret thread: %d\n", __FILE__, __func__, __LINE__, ret);
  
  return ret;
}
