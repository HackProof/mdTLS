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
#include "common.h"

#define CHAR_LENGTH    2048

#define SERVER_PUBLIC_KEY_PATH  "serverPk.pem"

// just for test
void found_fild()
{
    printf("Yes you found!!!!\n");
}

// file -> return char*
char *read_from_file(const char *filePath)
{
    printf("===>>> read_from_file()\n");
     FILE* file = fopen(filePath, "r");
    if (!file) {
        perror("Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char* pem_data = (char*)malloc(file_size + 1);
    if (!pem_data) {
        perror("Error allocating memory");
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(pem_data, 1, file_size, file);
    if (read_size != (size_t)file_size) {
        perror("Error reading file");
        free(pem_data);
        fclose(file);
        return NULL;
    }

    pem_data[file_size] = '\0'; // 문자열 끝에 null 문자 추가

    fclose(file);
    return pem_data;
}


// char* -> file
int write_to_file(const char* file_path, const char* data)
{
    FILE* file = fopen(file_path, "w");
    if (!file) {
        perror("Error opening file");
        return 0;
    }

    fputs(data, file);

    fclose(file);
    return 1;  
}


int read_der_from_file(const char *filename, unsigned char **der_data, int *der_length)
{
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error opening file for reading.\n");
        return 0;
    }

    fseek(file, 0, SEEK_END);
    *der_length = ftell(file);
    rewind(file);

    *der_data = (unsigned char *)malloc(*der_length);
    if (!*der_data) {
        fprintf(stderr, "Memory allocation error.\n");
        fclose(file);
        return 0;
    }

    size_t read = fread(*der_data, 1, *der_length, file);
    fclose(file);

    if (read != (size_t)*der_length) {
        fprintf(stderr, "Error reading DER data from file.\n");
        free(*der_data);
        return 0;
    }

    return 1;
}



int write_der_to_file(const char* file_path, const unsigned char* der_data, int der_length)
{
    FILE *file = fopen(file_path, "wb");
    if (!file) {
        fprintf(stderr, "Error opening file for writing.\n");
        return 0;
    }

    size_t written = fwrite(der_data, 1, der_length, file);
    fclose(file);

    if (written != (size_t)der_length) {
        fprintf(stderr, "Error writing DER data to file.\n");
        return 0;
    }

    return 1;
}


ECDSA_SIG *der_to_ecdsa_sig(const unsigned char *der_data, size_t der_length)
{
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &der_data, der_length);
    if (!ecdsa_sig) {
        fprintf(stderr, "Error converting DER to ECDSA_SIG.\n");
    }
    return ecdsa_sig;
}


X509 *der_to_x509(const unsigned char *der_data, size_t der_length) 
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (BIO_write(bio, der_data, der_length) <= 0) {
        fprintf(stderr, "Error writing DER data to BIO.\n");
        BIO_free(bio);
        return NULL;
    }

    X509 *x509_cert = d2i_X509_bio(bio, NULL);
    if (!x509_cert) {
        fprintf(stderr, "Error converting DER to X.509.\n");
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return x509_cert;
}


char *concat_str(const char* str1, const char* str2, const char* str3, const char* str4)
{
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    size_t len3 = (str3 == NULL) ? 0 : strlen(str3);
    size_t len4 = (str4 == NULL) ? 0 : strlen(str4);

    // total length
    size_t totalLen = len1 + len2 + len3 + len4;

    // assign memory for new string 
    char* result = (char*)malloc(totalLen + 1); // +1 is for \0
    
    if (result == NULL) {
        perror("fail for malloc in concat_str()");
        exit(EXIT_FAILURE);
    }

    // 각 문자열을 새로 할당한 메모리에 복사
    strcpy(result, str1);
    strcat(result, str2);
    if(str3 != NULL)    strcat(result, str3);
    if(str4 != NULL)    strcat(result, str4);

    return result;
}

EC_KEY* get_ECKey_private_from_PEM(const char *pemKey) {
    BIO *bio = BIO_new_mem_buf(pemKey, -1);

    if (bio == NULL) {
        perror("BIO_new_mem_buf failed");
        //handleErrors();
    }

    EC_KEY *ecKey = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);

    if (ecKey == NULL) {
        perror("PEM_read_bio_ECPrivateKey failed");
       // handleErrors();
    }

    BIO_free(bio);

     const BIGNUM *privateKeyBN = EC_KEY_get0_private_key(ecKey);

    if (privateKeyBN == NULL) {
        perror("EC_KEY_get0_private_key failed");
        //handleErrors();
        return NULL;
    }

    return ecKey;
}

EC_KEY* get_ECKey_public_from_PEM(const char *pemKey) {
    BIO *bio = BIO_new_mem_buf(pemKey, -1);

    if (bio == NULL) {
        perror("BIO_new_mem_buf failed");
        //handleErrors();
    }

    EC_KEY *ecKey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    

    if (ecKey == NULL) {
        perror("PEM_read_bio_ECPubKey failed");
       // handleErrors();
    }

    BIO_free(bio);

     const BIGNUM *publicKeyBN = EC_KEY_get0_public_key(ecKey);

    if (publicKeyBN == NULL) {
        perror("EC_KEY_get0_public_key failed");
        //handleErrors();
        return NULL;
    }

    return ecKey;
}

char *ECDSA_signature_to_string(const ECDSA_SIG *signature) {
    
    const BIGNUM *sig_r_d = NULL, *sig_s_d = NULL;
    ECDSA_SIG_get0(signature, &sig_r_d, &sig_s_d);
    
    char *r_str = BN_bn2hex(sig_r_d);
    char *s_str = BN_bn2hex(sig_s_d);

    size_t result_len = strlen(r_str) + strlen(s_str) + 2; // each string + space + Null character
    printf("sig len:::: %d\n", result_len);
    char *result = (char *)malloc(result_len);

    if (result == NULL) {
        fprintf(stderr, "fail to allocate memory\n");
        free(r_str);
        free(s_str);
        return NULL;
    }

    snprintf(result, result_len, "%s %s", r_str, s_str);

    // 메모리 해제
    free(r_str);
    free(s_str);

    return result;
}



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
EVP_PKEY* GetPublickeyFromCert(char *certPath)
{
    FILE *f;
    f = fopen(certPath, "rb");
 
    X509 *x = PEM_read_X509(f, NULL, NULL, NULL);
    if(x == NULL)   perror("x is null\n");
    fclose(f);

    EVP_PKEY *pubkey;
    pubkey = X509_get_pubkey(x);
    
    //******** writing public key in files (start)
    FILE *fp;
    int result;
    fp = fopen(SERVER_PUBLIC_KEY_PATH, "wb");
    result = PEM_write_PUBKEY(fp, pubkey);
    fclose(fp);
    //******** writing public key in files (end)

    return pubkey;
}

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


unsigned long get_current_microseconds()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (1000000 * (tv.tv_sec) + tv.tv_usec);
}