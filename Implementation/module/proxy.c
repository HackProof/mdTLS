#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
//#include "/home/mdtls/openssl-1.1.1w/crypto/ec/ec_local.h"   // for group->mond_data
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

void proxy_delegation(EC_KEY *key_pairs, const char *msg, ECDSA_SIG **rtn_sig, BIGNUM **rtn_Y_d)
{
    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);

    unsigned char digest[2048]; // EVP_MAX_MD_SIZE
    unsigned int dgst_len = 0;

    BIGNUM *kinv = NULL, *rp = NULL;
    ECDSA_SIG *local_signature = NULL;
    const BIGNUM *sig_r = NULL, *sig_s = NULL;

    hash_sha256(msg, strlen(msg), &digest, &dgst_len);

    printf("binary data of hash in proxy_delegation::: \n ");
    for (size_t i = 0; i < dgst_len; ++i) {
        printf("%02X ", digest[i]); 
    }
    printf("\n");

    //printf("@@@ sign setup \n");
    ECDSA_sign_setup(key_pairs, NULL, &kinv, &rp);
    //printf("@@@ sign message \n");
    local_signature = ECDSA_do_sign_ex(digest, dgst_len, kinv, rp, key_pairs);

    ECDSA_SIG_get0(local_signature, &sig_r, &sig_s);

    //BN_print(bio_out, sig_r);
    //BIO_printf(bio_out, " ::local sig r:: \n");

    //BN_print(bio_out, sig_s);
    //BIO_printf(bio_out, " ::local sig s:: \n");

    *rtn_sig = local_signature;
    *rtn_Y_d = rp;
}



int proxy_delegation_verify(EC_KEY *key_pairs, const char *msg, ECDSA_SIG *local_sig)
{
    unsigned char digest[2048]; // EVP_MAX_MD_SIZE
    unsigned int dgst_len = 0;
    
    hash_sha256(msg, strlen(msg), &digest, &dgst_len);
    printf("binary data of hash in proxy_delegation_verify::: \n ");
    for (size_t i = 0; i < dgst_len; ++i) {
        printf("%02X ", digest[i]); 
    }
    printf("\n");

    //printf("@@@ verify message \n");
    return ECDSA_do_verify(digest, dgst_len, local_sig, key_pairs);
}


void generate_hash_num(unsigned char *c, unsigned int c_len, BIGNUM **rtn_c_num)
{
    const EC_GROUP *group;
    const BIGNUM *order;
    int i;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    order = EC_GROUP_get0_order(group);
    i = BN_num_bits(order);

    //unsigned char c[2048]; // EVP_MAX_MD_SIZE
    //unsigned int c_len = 0;

    // generate hash c value
    //printf("==>>> proxysig.c > proxy_signing_key() > first hash\n");
    //hash_sha256(m_d, &c, &c_len);

    const BIGNUM *c_num = BN_new();

    if (8 * c_len > i)
        c_len = (i + 7) / 8;

    // conver hash c value to BIGNUM type
    if (!BN_bin2bn(c, c_len, c_num)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        return;
    }

    /* If still too long, truncate remaining bits with a shift */
    if ((8 * c_len > i) && !BN_rshift(c_num, c_num, 8 - (i & 0x7))) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        return;
    }

    if(c_num == NULL){
        printf("c_num is NULL \n");
        return;
    }

    *rtn_c_num = c_num;
}



// m_d: "QsIDmbQmbWarrant"
// c: H(m_d)
// r: H(m_d||c)
// t: r+d_mb*H(Yd||Warrant)
void proxy_signing_key(const char *m_d, const char *warrant, EC_KEY *origin_signer_key, EC_KEY *proxy_signer_key, BIGNUM *Y_d, BIGNUM **rtn_t, BIGNUM **rtn_r_num, BIGNUM **rtn_c_num)
{
    printf("@@@ proxy signing key \n");
    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);

    const EC_GROUP *group;
    const BIGNUM *order;
    int i;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    order = EC_GROUP_get0_order(group);
    //i = BN_num_bits(order);

    const BIGNUM *c_num;
    
    // generate hash c value start
    unsigned char c[2048]; // EVP_MAX_MD_SIZE
    unsigned int c_len = 0;
    
    //printf("==>>> proxysig.c > proxy_signing_key() > first hash\n");
    printf("[DEBUG] %s:%s:%d: Before hash_sha256() \n", __FILE__, __func__, __LINE__);
    hash_sha256(m_d, strlen(m_d), &c, &c_len);
    printf("[DEBUG] %s:%s:%d: After hash_sha256() \n", __FILE__, __func__, __LINE__);

    generate_hash_num(c, c_len, &c_num);
    printf("[DEBUG] %s:%s:%d: After generate_hash_num() \n", __FILE__, __func__, __LINE__);

    // const BIGNUM *c_num = BN_new();

    // // conver hash c value to BIGNUM type
    // if (!BN_bin2bn(c, c_len, c_num)) {
    //     ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
    //     return;
    // }

    // /* If still too long, truncate remaining bits with a shift */
    // if ((8 * c_len > i) && !BN_rshift(c_num, c_num, 8 - (i & 0x7))) {
    //     ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
    //     return;
    // }

    // if(c_num == NULL){
    //     printf("c_num is NULL \n");
    //     return;
    // }
    // generate hash c value end

    // concat message and warrant and hash c value in binary format
    unsigned char m_d_bin[2048]; // EVP_MAX_MD_SIZE
    unsigned int m_d_bin_len =0;
    str2bin(m_d, &m_d_bin, &m_d_bin_len);
    printf("[DEBUG] %s:%s:%d: After str2bin() \n", __FILE__, __func__, __LINE__);

    // print converted binary data
    //printf("Binary Data returned: \n");
    //for (size_t i=0; i < m_d_bin_len; i++) {
    //    printf("%02X ", m_d_bin[i]);
    //}
    //printf("\n");

    unsigned char m_d_c[2048];

    // concat binary data
    memcpy(m_d_c, m_d_bin, m_d_bin_len);
    printf("[DEBUG] %s:%s:%d: After memcpy() \n", __FILE__, __func__, __LINE__);
    memcpy((char*) m_d_c + m_d_bin_len, c, c_len);
    printf("[DEBUG] %s:%s:%d: After memcpy() \n", __FILE__, __func__, __LINE__);

    // copy binary data to m_d_c_final
    int m_d_c_final_len = m_d_bin_len+c_len;
    unsigned char m_d_c_final[m_d_c_final_len];
    memcpy(m_d_c_final, m_d_c, m_d_c_final_len);
    // for (size_t i = 0; i < m_d_bin_len+c_len; i++) {
    //     printf("%02X ", m_d_c[i]);
    // }
    // printf("\n");
     printf("[DEBUG] %s:%s:%d: After memcpy() \n", __FILE__, __func__, __LINE__);

    unsigned char r[2048]; // EVP_MAX_MD_SIZE
    unsigned int r_len = 0;
    //printf("==>>> proxysig.c > proxy_signing_key() > second hash\n");
    hash_sha256(m_d_c_final, strlen(m_d_c_final), &r, &r_len);
     printf("[DEBUG] %s:%s:%d: After hash_sha256() \n", __FILE__, __func__, __LINE__);

    
    const BIGNUM *priv_key;
    BN_CTX *ctx = BN_CTX_new(); // NULL;

    //printf("==>>> proxysig.c > proxy_signing_key() > start get proxy signer private key\n");
    printf("[DEBUG] %s:%s:%d: Start get proxy signer private key \n", __FILE__, __func__, __LINE__);
    
    priv_key = EC_KEY_get0_private_key(proxy_signer_key);
    printf("[DEBUG] %s:%s:%d: Start get proxy signer private key \n", __FILE__, __func__, __LINE__);

    if (priv_key == NULL) {
        //perror("Error getting proxy signer's private key\n");
        printf("[ERROR] %s:%s:%d: Error getting proxy signer's private key \n", __FILE__, __func__, __LINE__);
        return NULL;
    }
    printf("[DEBUG] %s:%s:%d: Start get proxy signer private key \n", __FILE__, __func__, __LINE__);

    if (!EC_KEY_can_sign(proxy_signer_key)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING);
        //perror("Error proxy signer's key cannot use for sign \n");
        printf("[ERROR] %s:%s:%d:Error proxy signer's key cannot use for sign \n", __FILE__, __func__, __LINE__);
        return NULL;
    }

    //const BIGNUM *r_num = BN_new();
    const BIGNUM *r_num;
    generate_hash_num(r, r_len, &r_num);
    
    // i = BN_num_bits(order);

    // if (8 * r_len > i)
    //     r_len = (i + 7) / 8;

    // if (!BN_bin2bn(r, r_len, r_num)) {
    //     ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
    //     return NULL;
    // }

    // /* If still too long, truncate remaining bits with a shift */
    // if ((8 * r_len > i) && !BN_rshift(r_num, r_num, 8 - (i & 0x7))) {
    //     ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
    //     return;
    // }

    // if(r_num == NULL){
    //     printf("r_num is NULL \n");
    //     return;
    // }

    //Y_d x좌표의 POINT 값 구하기
    EC_POINT *point_Y_d = EC_POINT_new(group);
    if (EC_POINT_set_compressed_coordinates_GFp(group, point_Y_d, Y_d, 1, ctx) != 1) {
        fprintf(stderr, "Failed to set compressed coordinates\n");
        BN_free(Y_d);
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return 1;
    }

    if(!EC_POINT_is_on_curve(group, point_Y_d, ctx)){
        printf("Not good point in signing key!!!!!!!!!! \n");
    }

    BIGNUM *hash_param1_x = BN_new();
    BIGNUM *hash_param1_y = BN_new();
    BIGNUM *hash_param1_y_2 = BN_new();
    BIGNUM *test_x = BN_new();
    BIGNUM *test_y = BN_new();
    BIGNUM *test_y_2 = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, point_Y_d, hash_param1_x, hash_param1_y, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        return;
    }

    BN_sub(hash_param1_y_2, order, hash_param1_y);

    int order_bits = BN_num_bits(order);
    //printf("order_bits:: %d\n", order_bits);
    if (!BN_set_bit(hash_param1_x, order_bits)
        || !BN_set_bit(hash_param1_y, order_bits)
        || !BN_set_bit(hash_param1_y_2, order_bits)
        || !BN_set_bit(test_x, order_bits)
        || !BN_set_bit(test_y, order_bits)
        || !BN_set_bit(test_y_2, order_bits)){
        printf("set bit failed!!!! \n");
        return;
    }    

    if (!BN_nnmod(test_x, hash_param1_x, order, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        return;
    }
    if (!BN_nnmod(test_y, hash_param1_y, order, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        return;
    }
    if (!BN_nnmod(test_y_2, hash_param1_y_2, order, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        return;
    }
    //BN_print(bio_out, hash_param1_x);
    //BIO_printf(bio_out, " ::x-coordinate of Y_d in proxy signing key:: \n");
    //BN_print(bio_out, hash_param1_y);
    //BIO_printf(bio_out, " ::y-coordinate of Y_d in proxy signing key :: \n");
    //BN_print(bio_out, hash_param1_y_2);
    //BIO_printf(bio_out, " ::y-coordinate#2 of Y_d in proxy signing key :: \n");

    size_t bin_hash_param1_len = EC_POINT_point2oct(group, point_Y_d, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (bin_hash_param1_len == 0) {
        fprintf(stderr, "Failed to get buffer size for EC_POINT\n");
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return ;
    }
    unsigned char *bin_hash_param1 = (unsigned char *)OPENSSL_malloc(bin_hash_param1_len);
    if (bin_hash_param1 == NULL) {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return ;
    }
    if (EC_POINT_point2oct(group, point_Y_d, POINT_CONVERSION_UNCOMPRESSED, bin_hash_param1, bin_hash_param1_len, NULL) != bin_hash_param1_len) {   // octetString(sequence of bytes)
        fprintf(stderr, "Failed to convert EC_POINT to octets\n");
        OPENSSL_free(bin_hash_param1);
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return;
    }

    printf("binary data of point Y_d in proxy signing key::: \n ");
    for (size_t i = 0; i < bin_hash_param1_len; ++i) {
        printf("%02X ", bin_hash_param1[i]); // 02X는 2자리 16진수로 출력하는 형식입니다.
    }
    printf("\n");


    unsigned char bin_warrant[2048];
    unsigned int bin_warrant_len =0;
    str2bin(warrant, &bin_warrant, &bin_warrant_len);

    // concat binary data
    unsigned char bin_hash_param1_warrant[2048];
    memcpy(bin_hash_param1_warrant, bin_hash_param1, bin_hash_param1_len);
    memcpy((char*) bin_hash_param1_warrant + bin_hash_param1_len, bin_warrant, bin_warrant_len);

    // copy binary data to m_d_c_final
    int bin_hash_param1_warrant_final_len = bin_hash_param1_len+bin_warrant_len;
    unsigned char bin_hash_param1_warrant_final[bin_hash_param1_warrant_final_len];
    memcpy(bin_hash_param1_warrant_final, bin_hash_param1_warrant, bin_hash_param1_warrant_final_len);

    printf("binary data of point Y_d||w in proxy signing key::: \n ");
    for (size_t i = 0; i < bin_hash_param1_warrant_final_len; ++i) {
        printf("%02X ", bin_hash_param1_warrant_final[i]); 
    }
    printf("\n");

    // Calculate the length of the Base64-decoded data
    //char *encodedData = base64_encode(bin_hash_param1_warrant_final, bin_hash_param1_warrant_final_len);
    //printf("!!! hash plain text in proxy signing key:: %s ", encodedData); 
    //printf("\n");
//
//
    unsigned char param1_warrant_hash[2048]; // EVP_MAX_MD_SIZE
    unsigned int param1_warrant_hash_len = 0;
    //hash_sha256(encodedData, &param1_warrant_hash, &param1_warrant_hash_len); // "WARRANT"
    hash_sha256(bin_hash_param1_warrant_final, bin_hash_param1_warrant_final_len, &param1_warrant_hash, &param1_warrant_hash_len); // "WARRANT"

    printf("binary data of h(Y_d||w) in proxy signing key::: \n ");
    for (size_t i = 0; i < param1_warrant_hash_len; ++i) {
        printf("%02X ", param1_warrant_hash[i]); 
    }
    printf("\n");

    //unsigned char bin_Y_d[2048];
    //int bin_Y_d_len = BN_bn2bin(Y_d, bin_Y_d);    

    //unsigned char bin_Y_d_warrant[2048];
    //// concat binary data
    //memcpy(bin_Y_d_warrant, bin_Y_d, bin_Y_d_len);
    //memcpy((char*) bin_Y_d_warrant + bin_Y_d_len, bin_warrant, bin_warrant_len);

    //// copy binary data to m_d_c_final
    //int bin_Y_d_warrant_final_len = bin_Y_d_len+bin_warrant_len;
    //unsigned char bin_Y_d_warrant_final[bin_Y_d_warrant_final_len];
    //memcpy(bin_Y_d_warrant_final, bin_Y_d_warrant, bin_Y_d_warrant_final_len);

    //unsigned char Y_d_warrant_hash[2048]; // EVP_MAX_MD_SIZE
    //unsigned int Y_d_warrant_hash_len = 0;
    //hash_sha256(bin_Y_d_warrant_final, &Y_d_warrant_hash, &Y_d_warrant_hash_len);    
    
    const BIGNUM *Y_d_warrant_num = BN_new();   //NULL;
    //i=0;
    i = BN_num_bits(order);
    if (8 * param1_warrant_hash_len > i)
        param1_warrant_hash_len = (i + 7) / 8;

    if (!BN_bin2bn(param1_warrant_hash, param1_warrant_hash_len, Y_d_warrant_num)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        return;
    }

    /* If still too long, truncate remaining bits with a shift */
    if ((8 * param1_warrant_hash_len > i) && !BN_rshift(Y_d_warrant_num, Y_d_warrant_num, 8 - (i & 0x7))) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        return;
    }

    if(Y_d_warrant_num == NULL){
        printf("Y_d_warrant_num is NULL \n");
        return;
    }

    BN_print(bio_out, Y_d_warrant_num);
    BIO_printf(bio_out, " ::H(Y_d||warrant) value in proxy signing key:: \n");
        
    // 주석에 포함된 함수와 mont_data는 직접 접근 불가!!
    // if (!bn_to_mont_fixed_top(t, Y_d_warrant_num, group->mont_data, ctx)   
    //     || !bn_mul_mont_fixed_top(t, t, priv_key, group->mont_data, ctx)) {
    //     ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
    //     return;
    // }
    // if (!bn_mod_add_fixed_top(t, t, r_num, order)) {
    //     ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
    //     return;
    // }

    // modulus 가져오려 하였으나 직접 접근 불가!!
    //const BIGNUM *modulus = EC_GROUP_get0_modulus(group);

    // 이 코드는 group 통해서 계수 a,b와 modulus prime p 값 가져오는 방법
    
    // BIGNUM *p = BN_new();
    // BIGNUM *a = BN_new();
    // BIGNUM *b = BN_new();
    // if(EC_GROUP_get_curve_GFp(group, p, a, b, ctx) == 1){
    // }

    const BN_MONT_CTX *mont_ctx = EC_GROUP_get_mont_data(group);
    BIGNUM *t = BN_new();
    if (t != NULL && r_num != NULL && order != NULL) {
        //printf("mul:: ==> %d \n", BN_mod_mul_montgomery(t, Y_d_warrant_num, priv_key, mont_ctx, ctx));
        //printf("mul:: ==> %d \n", BN_mul(t, Y_d_warrant_num, priv_key, ctx));
        //printf("bn_num_bits:: %d \n", BN_num_bits(t));
        //printf("add:: ==> %d \n", BN_mod_add(t, (const BIGNUM*) t, r_num, order, ctx));

        BN_mod_mul_montgomery(t, Y_d_warrant_num, priv_key, mont_ctx, ctx);
        BN_mul(t, Y_d_warrant_num, priv_key, ctx);
        BN_num_bits(t);
        BN_mod_add(t, (const BIGNUM*) t, r_num, order, ctx);

        *rtn_t = t;
        *rtn_r_num = r_num;
        *rtn_c_num = c_num;
    }else{
        printf("It's null \n");
    }   

    //printf("@@@ End of proxy signing key\n");
}



EC_KEY* generate_proxy_sign_key_pair(BIGNUM *t)
{
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if (!ec_key) {
        fprintf(stderr, "Error creating EC_KEY\n");
        return NULL;
    }

    if (!EC_KEY_set_private_key(ec_key, t)) {
        fprintf(stderr, "Error setting private key\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    // test add start
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *ec_point = EC_POINT_new(group);
    if (ec_point == NULL) {
        fprintf(stderr, "Failed to create EC_POINT\n");
        EC_KEY_free(ec_key);
        return NULL;
    }
    if (EC_POINT_mul(group, ec_point, t, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to multiply Bignum with EC_POINT\n");
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return NULL;
    }

    BIGNUM *hash_param1_x = BN_new();
    BIGNUM *hash_param1_y = BN_new();
    BIGNUM *hash_param1_y_2 = BN_new();
    BIGNUM *test_x = BN_new();
    BIGNUM *test_y = BN_new();
    BIGNUM *test_y_2 = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, ec_point, hash_param1_x, NULL, NULL)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        return;
    }

    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    //BN_print(bio_out, hash_param1_x);
    //BIO_printf(bio_out, " ::x-coordinate of t*G:: \n");



    char *public_key_str = EC_POINT_point2hex(group, ec_point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    //printf("Public Key generated t*G :::: %s\n", public_key_str);

    if (EC_KEY_set_public_key(ec_key, ec_point) != 1) {
        fprintf(stderr, "Failed to set public key for EC_KEY\n");
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return NULL;
    }
    // test add end
    return ec_key;
}



void proxy_sign(BIGNUM *t, const char *proxy_sign_msg, ECDSA_SIG **rtn_proxy_sig)
{
    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);

    unsigned char digest[2048]; // EVP_MAX_MD_SIZE
    unsigned int dgst_len = 0;
    hash_sha256(proxy_sign_msg, strlen(proxy_sign_msg), &digest, &dgst_len);


    BIGNUM *k_p_inv = NULL, *r_p = NULL;
    ECDSA_SIG *local_proxy_signature = NULL;
    const BIGNUM *sig_r_p = NULL, *sig_s_p= NULL;


    EC_KEY *t_key = generate_proxy_sign_key_pair(t);
    
    //printf("@@@ proxy signing \n");
    ECDSA_sign_setup(t_key, NULL, &k_p_inv, &r_p);
    local_proxy_signature = ECDSA_do_sign_ex(digest, dgst_len, k_p_inv, r_p, t_key);

    ECDSA_SIG_get0(local_proxy_signature, &sig_r_p, &sig_s_p);

    //BN_print(bio_out, sig_r_p);
    //BIO_printf(bio_out, " ::local proxy sig r:: \n");

    //BN_print(bio_out, sig_s_p);
    //BIO_printf(bio_out, " ::local proxy sig s:: \n");

    *rtn_proxy_sig = local_proxy_signature;

    printf("testing temp proxy verify reslt :: %d \n", ECDSA_do_verify(digest, dgst_len, local_proxy_signature, t_key));
    
}



EC_POINT* proxy_public_key(EC_KEY *original_signer_key, EC_KEY *proxy_signer_key, BIGNUM *r_hash_num, BIGNUM *c_hash_num, const BIGNUM *sig_x_Y_d, const BIGNUM *sig_s_d, const char *warrant)
{
    const EC_GROUP *group;
    const BIGNUM *order;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    //group = EC_KEY_get0_group(proxy_signer_key);
    order = EC_GROUP_get0_order(group);

    //const EC_POINT *generator = EC_GROUP_get0_generator(group);
    
    // calculate r*G
    //EC_POINT *result_1 = EC_POINT_new(group);       // r*G
    //if (EC_POINT_mul(group, result_1, r_hash_num, NULL, NULL, NULL) != 1) {
    //    fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
    //    EC_POINT_free(result_1);
    //    BN_free(r_hash_num);
    //    EC_GROUP_free(group);
    //    return;
    //}
    
    // calculate c*G + x_Y_d*Q_s
    EC_POINT *sum = EC_POINT_new(group); 
    const EC_POINT *Q_s = EC_KEY_get0_public_key(original_signer_key);
    if (EC_POINT_mul(group, sum, c_hash_num, Q_s, sig_x_Y_d, NULL) != 1) {
        fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
        EC_POINT_free(sum);
        BN_free(c_hash_num);
        EC_GROUP_free(group);
        return;
    }

    //// calculate c*G
    //EC_POINT *result_2 = EC_POINT_new(group);       // c*G
    //if (EC_POINT_mul(group, result_2, c_hash_num, NULL, NULL, NULL) != 1) {
    //    fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
    //    EC_POINT_free(result_2);
    //    BN_free(c_hash_num);
    //    EC_GROUP_free(group);
    //    return;
    //}
//
    //// calculate x_Y_d*Q_s
    //// get x_Y_d
    //// get Q_s
    //const EC_POINT *Q_s = EC_KEY_get0_public_key(original_signer_key);
    //EC_POINT *result_3 = EC_POINT_new(group);       // r * G
    //if (EC_POINT_mul(group, result_3, NULL, Q_s, sig_x_Y_d, NULL) != 1) {
    //    fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
    //    EC_POINT_free(result_3);
    //    BN_free(sig_x_Y_d);
    //    EC_GROUP_free(group);
    //    return;
    //}
//
    //// c*G + x_Y_d*Q_s
    //EC_POINT *sum = EC_POINT_new(group);
    //if (sum == NULL) {
    //    fprintf(stderr, "Failed to create EC_POINT (sum)\n");;
    //    EC_GROUP_free(group);
    //    return ;
    //}
    //if (EC_POINT_add(group, sum, result_2, result_3, NULL) != 1) {
    //    fprintf(stderr, "Failed to add EC_POINTS\n");
    //    EC_POINT_free(sum);
    //    EC_GROUP_free(group);
    //    return ;
    //}

    
    // calculate (s_d)^-1
    // get s_d
    BIGNUM *sig_s_d_inv = BN_new();
    if(BN_mod_inverse(sig_s_d_inv, sig_s_d, order, NULL) == NULL){
        fprintf(stderr, "Failed to compute inverse\n");
        BN_free(sig_s_d);
        BN_free(order);
        BN_free(sig_s_d_inv);
        return;
    }

    // calculate of hash param

    EC_POINT *hash_param1 = EC_POINT_new(group);
    if (EC_POINT_mul(group, hash_param1, NULL, sum, sig_s_d_inv, NULL) != 1) {
        fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
        EC_POINT_free(hash_param1);
        BN_free(sig_s_d_inv);
        EC_GROUP_free(group);
        return;
    }
    
    BN_CTX *ctx = BN_CTX_new(); // NULL;
    if(!EC_POINT_is_on_curve(group, hash_param1, ctx)){
        printf("Not good point!!!!!!!!!! \n");
    }

    
    //hash_param1 , Y_d 비교!!
    BIGNUM *hash_param1_x = BN_new();
    BIGNUM *hash_param1_y = BN_new();
    BIGNUM *hash_param1_y_2 = BN_new();
    BIGNUM *test_x = BN_new();
    BIGNUM *test_y = BN_new();
    BIGNUM *test_y_2 = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, hash_param1, hash_param1_x, NULL, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        return;
    }
    
    EC_POINT *point_Y_d = EC_POINT_new(group);
    if (EC_POINT_set_compressed_coordinates_GFp(group, point_Y_d, hash_param1_x, 1, ctx) != 1) {
        fprintf(stderr, "Failed to set compressed coordinates\n");
        BN_free(hash_param1_x);
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return 1;
    }


    if (!EC_POINT_get_affine_coordinates_GFp(group, point_Y_d, hash_param1_x, hash_param1_y, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        return;
    }

    BN_sub(hash_param1_y_2, order, hash_param1_y);
    
    
    int order_bits = BN_num_bits(order);
    //printf("order_bits:: %d\n", order_bits);
    if (!BN_set_bit(hash_param1_x, order_bits)
        || !BN_set_bit(hash_param1_y, order_bits)
        || !BN_set_bit(hash_param1_y_2, order_bits)
        || !BN_set_bit(test_x, order_bits)
        || !BN_set_bit(test_y_2, order_bits)
        || !BN_set_bit(test_y, order_bits)){
        printf("set bit failed!!!! \n");
        return;
    }    

    if (!BN_nnmod(test_x, hash_param1_x, order, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        return;
    }
    if (!BN_nnmod(test_y, hash_param1_y, order, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        return;
    }
    if (!BN_nnmod(test_y_2, hash_param1_y_2, order, ctx)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
        return;
    }


    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    //BN_print(bio_out, sig_x_Y_d);
    //BIO_printf(bio_out, " ::signature r:: \n");
    //BN_print(bio_out, sig_s_d);
    //BIO_printf(bio_out, " ::signature s:: \n");
    //BN_print(bio_out, hash_param1_x);
    //BIO_printf(bio_out, " ::x-coordinate of Y_d in proxy public key:: \n");
    //BN_print(bio_out, hash_param1_y);
    //BIO_printf(bio_out, " ::y-coordinate of Y_d in proxy public key :: \n");
    //BN_print(bio_out, test_y_2);
    //BIO_printf(bio_out, " ::y-coordinate#2 of Y_d in proxy public key :: \n");   
    
    //hash_param1 , Y_d 비교!! end

    size_t bin_hash_param1_len = EC_POINT_point2oct(group, point_Y_d, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (bin_hash_param1_len == 0) {
        fprintf(stderr, "Failed to get buffer size for EC_POINT\n");
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return ;
    }

    unsigned char *bin_hash_param1 = (unsigned char *)OPENSSL_malloc(bin_hash_param1_len);
    if (bin_hash_param1 == NULL) {
        fprintf(stderr, "Failed to allocate memory for buffer\n");
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return ;
    }

    if (EC_POINT_point2oct(group, point_Y_d, POINT_CONVERSION_UNCOMPRESSED, bin_hash_param1, bin_hash_param1_len, NULL) != bin_hash_param1_len) {
        fprintf(stderr, "Failed to convert EC_POINT to octets\n");
        OPENSSL_free(bin_hash_param1);
        EC_POINT_free(point_Y_d);
        EC_GROUP_free(group);
        return;
    }

    printf("binary data of point Y_d in proxy public key::: \n ");
    for (size_t i = 0; i < bin_hash_param1_len; ++i) {
        printf("%02X ", bin_hash_param1[i]); // 02X는 2자리 16진수로 출력하는 형식입니다.
    }
    printf("\n");


    unsigned char bin_warrant[2048];
    unsigned int bin_warrant_len =0;
    str2bin(warrant, &bin_warrant, &bin_warrant_len);

    // concat binary data
    unsigned char bin_hash_param1_warrant[2048];
    memcpy(bin_hash_param1_warrant, bin_hash_param1, bin_hash_param1_len);
    memcpy((char*) bin_hash_param1_warrant + bin_hash_param1_len, bin_warrant, bin_warrant_len);

    // copy binary data to m_d_c_final
    int bin_hash_param1_warrant_final_len = bin_hash_param1_len+bin_warrant_len;
    unsigned char bin_hash_param1_warrant_final[bin_hash_param1_warrant_final_len];
    memcpy(bin_hash_param1_warrant_final, bin_hash_param1_warrant, bin_hash_param1_warrant_final_len);

    printf("binary data of point Y_d||w in proxy public key::: \n ");
    for (size_t i = 0; i < bin_hash_param1_warrant_final_len; ++i) {
        printf("%02X ", bin_hash_param1_warrant_final[i]);
    }
    printf("\n");

    // Calculate the length of the Base64-decoded data
    //char *encodedData = base64_encode(bin_hash_param1_warrant_final, bin_hash_param1_warrant_final_len);
    //printf("!!! hash plain text in proxy public key:: %s ", encodedData); 
    //printf("\n");

    unsigned char param1_warrant_hash[2048]; // EVP_MAX_MD_SIZE
    unsigned int param1_warrant_hash_len = 0;
    hash_sha256(bin_hash_param1_warrant_final, bin_hash_param1_warrant_final_len, &param1_warrant_hash, &param1_warrant_hash_len); // "WARRANT"

    printf("binary data of h(Y_d||w) in proxy public key::: \n ");
    for (size_t i = 0; i < param1_warrant_hash_len; ++i) {
        printf("%02X ", param1_warrant_hash[i]); 
    }
    printf("\n");

    const BIGNUM *param1_warrant_hash_num = BN_new();   //NULL;
    int i = BN_num_bits(order);
    if (8 * param1_warrant_hash_len > i)
        param1_warrant_hash_len = (i + 7) / 8;

    if (!BN_bin2bn(param1_warrant_hash, param1_warrant_hash_len, param1_warrant_hash_num)) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        return;
    }

    /* If still too long, truncate remaining bits with a shift */
    if ((8 * param1_warrant_hash_len > i) && !BN_rshift(param1_warrant_hash_num, param1_warrant_hash_num, 8 - (i & 0x7))) {
        ECerr(EC_F_OSSL_ECDSA_SIGN_SIG, ERR_R_BN_LIB);
        return;
    }

    if(param1_warrant_hash_num == NULL){
        printf("param1_warrant_hash_num is NULL \n");
        return;
    }

    BN_print(bio_out, param1_warrant_hash_num);
    BIO_printf(bio_out, " ::H(Y_d||warrant) value in proxy public key:: \n");

    // calculate hash_value*Q_mb
    // get Q_mb
    //const EC_POINT *Q_mb = EC_KEY_get0_public_key(proxy_signer_key);
    //EC_POINT *result_4 = EC_POINT_new(group);       // r * G
    //if (EC_POINT_mul(group, result_4, NULL, Q_mb, param1_warrant_hash_num, NULL) != 1) {
    //    fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
    //    EC_POINT_free(result_4);
    //    BN_free(param1_warrant_hash_num);
    //    EC_GROUP_free(group);
    //    return;
    //}

    // calculate r*G + hash_value*Q_mb
    //EC_POINT *PKP = EC_POINT_new(group);
    //if (PKP == NULL) {
    //    fprintf(stderr, "Failed to create EC_POINT (PKP)\n");;
    //    EC_GROUP_free(group);
    //    return ;
    //}
    //if (EC_POINT_add(group, PKP, result_1, result_4, NULL) != 1) {
    //    fprintf(stderr, "Failed to add EC_POINTS\n");
    //    EC_POINT_free(PKP);
    //    EC_GROUP_free(group);
    //    return ;
    //}

    // calculate r*G + hash_value*Q_mb
    EC_POINT *PKP = EC_POINT_new(group);
    // get Q_mb
    const EC_POINT *Q_mb = EC_KEY_get0_public_key(proxy_signer_key);
    if (EC_POINT_mul(group, PKP, r_hash_num, Q_mb, param1_warrant_hash_num, NULL) != 1) {
        fprintf(stderr, "Failed to multiply EC_POINT and BIGNUM\n");
        EC_POINT_free(PKP);
        BN_free(param1_warrant_hash_num);
        EC_GROUP_free(group);
        return;
    }

    if(!EC_POINT_is_on_curve(group, hash_param1, ctx)){
        printf("Not good point for PKP!!!!!!!!!! \n");
    }


    BIGNUM *PKP_x = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, PKP, PKP_x, NULL, NULL)) {
        ECerr(EC_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
        return;
    }

    //BN_print(bio_out, PKP_x);
    //BIO_printf(bio_out, " ::x-coordinate of PKP:: \n");


    //char *public_key_str = EC_POINT_point2hex(group, PKP, POINT_CONVERSION_UNCOMPRESSED, NULL);
    //printf("Public Key generated #1: %s\n", public_key_str);

    return PKP;
}


int proxy_sign_verify(EC_POINT *PKP, const char *msg, ECDSA_SIG *proxy_sig)
{
    BIO *bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    //char *public_key_str = EC_POINT_point2hex(group, PKP, POINT_CONVERSION_UNCOMPRESSED, NULL);
    //printf("Public Key generated #2: %s\n", public_key_str);

    const BIGNUM *sig_r_p = NULL, *sig_s_p= NULL;
    ECDSA_SIG_get0(proxy_sig, &sig_r_p, &sig_s_p);

    //BN_print(bio_out, sig_r_p);
    //BIO_printf(bio_out, " ::verify proxy sig r:: \n");
    //BN_print(bio_out, sig_s_p);
    //BIO_printf(bio_out, " ::verify proxy sig s:: \n");


    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (EC_KEY_set_public_key(key, PKP) != 1) {
        fprintf(stderr, "Failed to set EC_POINT to EC_KEY\n");
        EC_POINT_free(PKP);
        EC_KEY_free(key);
        return 1;
    }

    const EC_POINT *public_key = EC_KEY_get0_public_key(key);
    //char *public_key_str_from_keypair = EC_POINT_point2hex(group, public_key, POINT_CONVERSION_UNCOMPRESSED, NULL);
    //printf("Public Key generated #3: %s\n", public_key_str_from_keypair);

    unsigned char digest[2048]; // EVP_MAX_MD_SIZE
    unsigned int dgst_len = 0;
    
    hash_sha256(msg, strlen(msg), &digest, &dgst_len);

    //printf("@@@ verify message \n");
    int verify_result = ECDSA_do_verify(digest, dgst_len, proxy_sig, key);
    if (verify_result == 1) {
        // 서명이 유효함
        printf("Signature verification succeeded\n");
        return verify_result;
    } else {
        // 서명이 유효하지 않음
        printf("Signature verification failed\n");

        // 에러 스택 출력
        unsigned long err = ERR_get_error();
        printf("%d \n", err);
        while (err != 0) {
            fprintf(stderr, "OpenSSL Error: %s\n", ERR_error_string(err, NULL));
            err = ERR_get_error();
        }

        return verify_result;
    }

}


// rtn_dgst_len: bytes of hash (=length of array, each array means 1byte)
void hash_sha256(const unsigned char *msg, unsigned int msg_len, unsigned char *rtn_digest, unsigned int *rtn_dgst_len)
{
    EVP_MD_CTX *mctx = NULL;
    unsigned char local_digest[2048]; // EVP_MAX_MD_SIZE
    unsigned int local_dgst_len = 0;

    mctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mctx, EVP_get_digestbynid(NID_sha256), NULL);
    EVP_DigestUpdate(mctx, msg, msg_len);
    EVP_DigestFinal_ex(mctx, local_digest, &local_dgst_len);

    //printf("plain text length:: %d \n", strlen(msg));
    //printf("plain text:: %s \n", msg);
    printf("plain text in hash_sha256:: \n");
    for (int i=0; i<msg_len; i++) {
       printf("%02X ", msg[i]);
    }
    printf("\n");
    printf("hash length:: %d\n", local_dgst_len);
    printf("hash value in hash_sha256:: \n");
    for (int i=0; i<local_dgst_len; i++) {
       printf("%02X ", local_digest[i]);
    }
    printf("\n");

    *rtn_dgst_len = local_dgst_len;
    //strcpy(rtn_digest, local_digest);
    memcpy(rtn_digest, local_digest, local_dgst_len);

    printf("copied hash value in hash_sha256:: \n");
    for (int i=0; i<*rtn_dgst_len; i++) {
       printf("%02X ", rtn_digest[i]);
    }
    printf("\n");

}

void str2bin(const char *str, unsigned char *bin, unsigned int *bin_len)
{
    // length of string
    size_t len = strlen(str);

    // array to save binary data
    unsigned char binaryData[len];

    // convert string to binary
    for (size_t i = 0; i < len; i++) {
        binaryData[i] = (unsigned char)str[i];
    }

    // print converted binary data
    //printf("Binary Data: \n");
    //for (size_t i = 0; i < len; i++) {
    //    printf("%02X ", binaryData[i]);
    //}
    //printf("\n");

    *bin_len = len;
    strcpy(bin, binaryData);

    return 0;
}

char* base64_encode(const char* input, size_t length) {
    BIO *bio, *b64;
    FILE* stream;
    size_t encoded_length = 4 * ((length + 2) / 3);
    //printf("entered to base64 encode\n");

    char* buffer = (char*)malloc(encoded_length + 1);
    if (!buffer) {
        fprintf(stderr, "Memory allocation error.\n");
        exit(EXIT_FAILURE);
        return "";
    }
    //printf("create buffer\n");
    stream = fmemopen(buffer, encoded_length, "w");
    if (!stream) {
        perror("fmemopen");
        free(buffer);
        exit(EXIT_FAILURE);
        return "";
    }
   // printf("fmem open\n");

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_fp(stream, BIO_CLOSE);
    bio = BIO_push(b64, bio);

    if (BIO_write(bio, input, length) <= 0) {
        BIO_free_all(bio);
        perror("BIO_write");
        free(buffer);
        exit(EXIT_FAILURE);
        return "";
    }
    //printf("Bio write\n");

    if (BIO_flush(bio) <= 0) {
        BIO_free_all(bio);
        perror("BIO_flush");
        free(buffer);
        exit(EXIT_FAILURE);
        return "";
    }
    //printf("Bio flush\n");

    buffer[encoded_length] = '\0';
    
    
    //BIO_free_all(bio);
    //fclose(stream);

    return buffer;
}
