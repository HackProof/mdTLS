GCC=gcc
CFLAGS= -o 

CMMLIB=../common.o ../module/proxy.o

EXEC_SMB=smb
SRC_SMB=smb.c mssl.c table.c
EXEC_CMB=cmb
SRC_CMB=cmb.c mssl.c table.c

KEY_SMB=/home/mdtls/apps/middlebox/rsa_cert/smb.key
CERT_SMB=/home/mdtls/apps/middlebox/rsa_cert/smb.pem

FLAGS=-L /usr/lib
LDFLAGS=-lssl -lcrypto 

HOST=127.0.0.1
PORT_SMB=8082
PORT_CMB=8083
NUM_OF_THREADS=1

FORWARD_FILE_SMB=forward/forward_smb.txt

default: mdtls

mdtls:
	${GCC} ${CMMLIB} -DMDTLS ${CFLAGS} ${EXEC_SMB} ${SRC_SMB} ${FLAGS} ${LDFLAGS}
	# ${GCC} ${CMMLIB} ${CFLAGS} ${EXEC_CMB} ${SRC_CMB} ${FLAGS} ${LDFLAGS}

smstart:
	./${EXEC_SMB} ${PORT_SMB} ${CERT_SMB} ${KEY_SMB} ${FORWARD_FILE_SMB} 1 0 > log_smb.out

cmstart:
	./${EXEC_CMB} ${PORT_CMB} ${FORWARD_FILE_CMB} 0 0
