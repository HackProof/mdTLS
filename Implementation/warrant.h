#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <time.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

typedef struct _mdtls_warrant
{
    char *entityName;
    int t;
} warrant;