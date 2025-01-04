#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>


EC_POINT* proxy_public_key(EC_KEY *original_signer_key, EC_KEY *proxy_signer_key, BIGNUM *r_hash_num, BIGNUM *c_hash_num, const BIGNUM *sig_x_Y_d, const BIGNUM *sig_s_d, const char *warrant);
char* base64_encode(const char* input, size_t length);

void proxy_delegation(EC_KEY *key_pairs, const char *msg, ECDSA_SIG **rtn_sig, BIGNUM **rtn_Y_d);

int proxy_delegation_verify(EC_KEY *key_pairs, const char *msg, ECDSA_SIG *local_sig);

void generate_hash_num(unsigned char *c, unsigned int c_len, BIGNUM **rtn_c_num);

void proxy_signing_key(const char *m_d, const char *warrant, EC_KEY *origin_signer_key, EC_KEY *proxy_signer_key, BIGNUM *Y_d, BIGNUM **rtn_t, BIGNUM **rtn_r_num, BIGNUM **rtn_c_num);

EC_KEY* generate_proxy_sign_key_pair(BIGNUM *t);

void proxy_sign(BIGNUM *t, const char *proxy_sign_msg, ECDSA_SIG **rtn_proxy_sig);

EC_POINT* proxy_public_key(EC_KEY *original_signer_key, EC_KEY *proxy_signer_key, BIGNUM *r_hash_num, BIGNUM *c_hash_num, const BIGNUM *sig_x_Y_d, const BIGNUM *sig_s_d, const char *warrant);

int proxy_sign_verify(EC_POINT *PKP, const char *msg, ECDSA_SIG *proxy_sig);

void hash_sha256(const unsigned char *msg, unsigned int msg_len, unsigned char *rtn_digest, unsigned int *rtn_dgst_len);

void str2bin(const char *str, unsigned char *bin, unsigned int *bin_len);

char* base64_encode(const char* input, size_t length) ;
