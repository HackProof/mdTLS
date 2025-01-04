GCC=gcc -g
CFLAGS= -o 

CMMLIB=../common.o ../module/proxy.o

EXEC=server
SRC=server.c
CERT=matls_key_cert/matls_cert.crt
KEY=matls_key_cert/matls_priv.pem

FLAGS=-L /usr/lib
LDFLAGS=-lssl -lcrypto 

#HOST=127.0.0.1
PORT=8081
NUM_OF_THREADS=1

default: mdtls

mdtls:
	${GCC} ${CMMLIB} -DMDTLS ${CFLAGS} ${EXEC} ${SRC} ${FLAGS} ${LDFLAGS}

sstart:
	./${EXEC} ${PORT} ${CERT} ${KEY} > log_srvr.out
