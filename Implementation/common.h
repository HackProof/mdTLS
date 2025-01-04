#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "warrant.h"

#define CHAR_LENGTH    2048

#define SERVER_PUBLIC_KEY_PATH  "serverPk.pem"

#define SECRET_LENGTH 32
#define CLIENT 0
#define SERVER 1
#define SSL_MAX_ACCOUNTABILITY_KEY_LENGTH 32
#define TLS_MD_ID_SIZE 32
#define TLS_MD_HASH_SIZE 32
#define TLS_MD_HMAC_SIZE 32

//const char *PERSON_FORMAT_IN = "(%[^,], %lld)"; // ,를 읽지말고 ,직전까지만 읽어라. %s는 whitespacce까지 읽으므로
//const char *PERSON_FORMAT_OUT = "(%s, %lld)\n";

// just for test
void found_fild(void);

// file -> return char*
char *read_from_file(const char *filePath);

// char* -> file
int write_to_file(const char* file_path, const char* data);

int read_der_from_file(const char *filename, unsigned char **der_data, int *der_length);
int write_der_to_file(const char* file_path, const unsigned char* der_data, int der_length);
ECDSA_SIG *der_to_ecdsa_sig(const unsigned char *der_data, size_t der_length);
X509 *der_to_x509(const unsigned char *der_data, size_t der_length);

char *concat_str(const char* str1, const char* str2, const char* str3, const char* str4);

EC_KEY* get_ECKey_private_from_PEM(const char *pemKey);

EC_KEY* get_ECKey_public_from_PEM(const char *pemKey);


char *ECDSA_signature_to_string(const ECDSA_SIG *signature);

EVP_PKEY* GetPublickeyFromCert(char *certPath);

unsigned long get_current_microseconds();

// 일반파일에서 PEM 문자열 그대로 가져오는 함수
// uint8_t* extractPubKey(char* filepath)
// {
//     FILE *f;
//     f = fopen(filepath, "rb");
//     uint8_t buff[CHAR_LENGTH];
//     static uint8_t publickey[CHAR_LENGTH] = "";       // static 안 붙이면 scope를 벗어난 함수 밖에서는 null 값을 받게 됨

//     if(strlen(publickey) > 0)
//         memset(publickey, 0, CHAR_LENGTH);
    
//     if(strcmp(publickey, "") == 0){ // static이기 때문에 값이 존재하는 경우 2번째 실행 시 뒤에 값을 덧붙임 
//         while(!feof(f)){
//             if(buff!=NULL){
//                 if(fgets(buff, CHAR_LENGTH, f) == NULL) break;
//                 else{
//                     strcat(publickey, buff);
//                     //printf("============================");
//                     //printf("%s", buff);
//                 }
//             }
//         }
//     }
//     fclose(f);
//     //printf("result of this function\n");
//     //printf("%s\n", publickey);
//     return publickey;
// }


// GetPublickey_FAIL() 함수처럼 인증서 파일을 그대로 열어서 PEM_read_PUBKEY를 통해 public key를 추출하려하면 NULL이 뱉어짐
// GetPublickey() 함수와 같이 PEM 파일을 읽어들여 X509 타입에 저장 후 X509_get_pubkey() 함수를 통해서 X509의 PUBLIC KEY를 EVP_PEKY 타입에 저장해야 함

// warrant 구조체를 base64로 encoding
/*
uint8_t* encodingWarrant(warrant w)
{
    FILE *file;
    file = fopen("warrant.dat", "w+"); 
    //if(file == NULL)    return 0;

    fprintf(file, PERSON_FORMAT_OUT, w.entityName, w.t);
    fseek(file, 0, SEEK_SET);

    uint8_t buff[CHAR_LENGTH];
    uint8_t warrantString[CHAR_LENGTH] = "";
    if(strlen(warrantString) > 0)
        printf("already has warrant string\n");
    
    if(strcmp(warrantString, "") == 0){ // static이기 때문에 값이 존재하는 경우 2번째 실행 시 뒤에 값을 덧붙임 
        while(!feof(file)){
            if(buff!=NULL){
                if(fgets(buff, CHAR_LENGTH, file) == NULL) break;
                else{
                    strcat(warrantString, buff);
                    //printf("============================");
                    //printf("%s", buff);
                }
            }
        }
    }
    fclose(file);

    //printf("warrant String!! \n");
    //printf("%s\n", warrantString);

    // encode warrant string in base64
    size_t encodedLen;
    uint8_t *encoded = base64_encode(warrantString, strlen(warrantString)+1, &encodedLen);
    //printf("warrant encoded\n");
    //printf("%s\n", *encoded);

    return encoded;
}
*/

/*
void writeToFile(char *param, char *filePath)
{
    FILE *check_f;
    check_f = fopen(filePath, "wb");
    fprintf(check_f, param);
    fclose(check_f);
}

char* readFromFile(char *filePath)
{
    FILE *f;
    f = fopen(filePath, "rb");
    char buff[2048];
    static char receiveStr[2048] = "";       // static 안 붙이면 scope를 벗어난 함수 밖에서는 null 값을 받게 됨
    
    if(strlen(receiveStr) > 0)
        memset(receiveStr, 0, CHAR_LENGTH);

    if(strcmp(receiveStr, "") == 0){ // static이기 때문에 값이 존재하는 경우 2번째 실행 시 뒤에 값을 덧붙임 
        while(!feof(f)){
            if(buff!=NULL){
                if(fgets(buff, 2048, f) == NULL) break;
                else{
                    strcat(receiveStr, buff);
                    //printf("============================");
                    //printf("%s", buff);
                }
            }
        }
    }
    fclose(f);
    return receiveStr;
}

void checkHashCode()
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char message[] = "hello";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    OpenSSL_add_all_digests(); // 해시 알고리즘 등록

    md = EVP_get_digestbyname("SHA256"); // 원하는 해시 알고리즘 선택

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message, sizeof(message));
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);

    EVP_MD_CTX_destroy(mdctx);

    printf("===========checked hash code start===========\n");
    for (int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n===========checked hash code end===========\n");
}
*/