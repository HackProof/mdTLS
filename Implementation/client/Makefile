GCC=gcc
CFLAGS= -o 

CMMLIB=../common.o ../module/proxy.o

EXEC=client
SRC=client.c

FLAGS=-L /usr/lib
LDFLAGS=-lssl -lcrypto 

HOST=127.0.0.1
PORT=8082
NUM_OF_THREADS=1

default: mdtls

mdtls:
	${GCC} ${CMMLIB} -DMDTLS ${CFLAGS} ${EXEC} ${SRC} ${FLAGS} ${LDFLAGS}

cstart:
	./${EXEC} ${HOST} ${PORT} 
