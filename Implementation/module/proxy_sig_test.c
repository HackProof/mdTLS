#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
//#include "/home/mdtls/openssl-1.1.1w/crypto/ec/ec_local.h"   // group->mond_data를 위함
//#include "../openssl-1.1.1w/crypto/ec/ec_local.h"
//#include <openssl-1.1.1w/crypto/ec/ec_local.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include "proxy.h"
//#include "crypto/bn.h"


EC_POINT* proxy_public_key(EC_KEY *original_signer_key, EC_KEY *proxy_signer_key, BIGNUM *r_hash_num, BIGNUM *c_hash_num, const BIGNUM *sig_x_Y_d, const BIGNUM *sig_s_d, const char *warrant);
char* base64_encode(const char* input, size_t length);

uint64_t rdtsc() {
    uint32_t lo, hi;
    __asm__ __volatile__ (
        "rdtsc"                 // RDTSC 명령어 실행
        : "=a" (lo), "=d" (hi)  // EAX와 EDX에 결과 저장
    );
    return ((uint64_t)hi << 32) | lo; // 상위 32비트와 하위 32비트를 결합
}


int main(int argc, char const *argv[])
{
    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);

    EC_KEY *origin_signer_key = NULL, *proxy_signer_key = NULL;
    ECDSA_SIG *delegate_signature = NULL, *proxy_signature = NULL;

    const BIGNUM *sig_r_d = NULL, *sig_s_d = NULL, *Y_d = NULL, *t, *r_num, *c_num;
    
    // ecdsa key setup
    origin_signer_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    proxy_signer_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (origin_signer_key == NULL || proxy_signer_key == NULL) {
        // error
        printf("key structure is failed\n");
        return -1;
    }

    uint64_t ec_key_start = rdtsc();
    // ecdsa key pair
    if (!EC_KEY_generate_key(origin_signer_key)) {
        // error
        EC_KEY_free(origin_signer_key);
        return -1;
    }
    uint64_t ec_key_end = rdtsc();
    printf("Elapsed ec_key gen CPU cycles: %llu\n", (ec_key_end - ec_key_start));

    if (!EC_KEY_generate_key(proxy_signer_key)) {
        // error
        EC_KEY_free(proxy_signer_key);
        return -1;
    }

    const char *msg = "QsIDmbQmbWarrant";

    // ECDSA sign
    uint64_t ecdsa_sign_start = rdtsc();
    proxy_delegation(origin_signer_key, msg, &delegate_signature, &Y_d);
    uint64_t ecdsa_sign_end = rdtsc(); // 끝 시간 측정
    printf("Elapsed ecdsa sign CPU cycles: %llu\n", (ecdsa_sign_end - ecdsa_sign_start));

    // get (r,s) of signature
    ECDSA_SIG_get0(delegate_signature, &sig_r_d, &sig_s_d);

    //BN_print(bio_out, sig_r_d);
    //BIO_printf(bio_out, " ::sig_r_d:: \n");

    //BN_print(bio_out, sig_s_d);
    //BIO_printf(bio_out, " ::sig_s_d:: \n");

    //BN_print(bio_out, Y_d);
    //BIO_printf(bio_out, " ::x-coordinate of Y_d:: \n");

    // Verify ECDSA signature
    uint64_t ecdsa_verif_start = rdtsc();
    printf("verify reslt :: %d \n",proxy_delegation_verify(origin_signer_key, msg, delegate_signature));
    uint64_t ecdsa_verif_end = rdtsc(); // 끝 시간 측정
    printf("Elapsed ecdsa verify CPU cycles: %llu\n", (ecdsa_verif_end - ecdsa_verif_start));

    // Generate Proxy signing key
    uint64_t proxy_skp_start = rdtsc();
    const char *proxy_m_d = "QsIDmbQmbWarrant";
    const char *proxy_warrant = "Warrant";
    proxy_signing_key(proxy_m_d, proxy_warrant, origin_signer_key, proxy_signer_key, Y_d, &t, &r_num, &c_num);
    uint64_t proxy_skp_end = rdtsc(); // 끝 시간 측정
    printf("Elapsed proxy skp CPU cycles: %llu\n", (proxy_skp_end - proxy_skp_start));

    // Generate Proxy signature
    uint64_t proxy_sign_start = rdtsc();
    const char *proxy_sign_msg = "message";
    proxy_sign(t, proxy_sign_msg, &proxy_signature);
    uint64_t proxy_sign_end = rdtsc(); // 끝 시간 측정
    printf("Elapsed proxy sign CPU cycles: %llu\n", (proxy_sign_end - proxy_sign_start));

    // Generate Proxy public key
    uint64_t proxy_pkp_start = rdtsc();
    EC_POINT *PKP = proxy_public_key(origin_signer_key, proxy_signer_key, r_num, c_num, sig_r_d, sig_s_d, proxy_warrant);
    uint64_t proxy_pkp_end = rdtsc(); // 끝 시간 측정
    printf("Elapsed proxy pkp CPU cycles: %llu\n", (proxy_pkp_end - proxy_pkp_start));

    // Verify proxy signature
    uint64_t proxy_verif_start = rdtsc();
    printf("proxy verify reslt :: %d \n",proxy_sign_verify(PKP, proxy_sign_msg, proxy_signature));
    uint64_t proxy_verif_end = rdtsc(); // 끝 시간 측정
    printf("Elapsed proxy verify CPU cycles: %llu\n", (proxy_verif_end - proxy_verif_start));
    return 0;
}