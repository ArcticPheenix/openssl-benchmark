#include "rsa_bench.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

static void keygen_func(void* arg) {
    RSAArg* rsa_arg = (RSAArg*)arg;
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4); // Use 65537 exponent
    RSA_generate_key_ex(rsa, rsa_arg->key_size, e, NULL);
    RSA_free(rsa);
    BN_free(e);
}

void bench_keygen(int key_size, int iterations, BenchmarkResult* result) {
    RSAArg arg = { .key_size = key_size };
    time_per_iteration(keygen_func, &arg, iterations, result);
}

static void sign_func(void* arg) {
    RSAArg* rsa_arg = (RSAArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t sig_len;
    unsigned char sig[512]; // Should be sufficient for RSA signatures
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_arg->pkey);
    EVP_DigestSign(ctx, sig, &sig_len, rsa_arg->data, rsa_arg->data_size);
    EVP_MD_CTX_free(ctx);
}

void bench_sign(int key_size, int data_size, int iterations, BenchmarkResult* result) {
    // Setup key and data
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, key_size, e, NULL);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    unsigned char* data = malloc(data_size);
    RAND_bytes(data, data_size);

    RSAArg arg = { .key_size = key_size, .data_size = data_size, .data = data, .pkey = pkey };
    time_total_delta(sign_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey); // Frees rsa too
    BN_free(e);
}

static void verify_func(void* arg) {
    RSAArg* rsa_arg = (RSAArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t sig_len;
    unsigned char sig[512];
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_arg->pkey); // Sign first
    EVP_DigestSign(ctx, sig, &sig_len, rsa_arg->data, rsa_arg->data_size);
    EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, rsa_arg->pkey);
    EVP_DigestVerify(ctx, sig, sig_len, rsa_arg->data, rsa_arg->data_size);
    EVP_MD_CTX_free(ctx);
}

void bench_verify(int key_size, int data_size, int iterations, BenchmarkResult* result) {
    // Setup key and data (same as sign)
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, key_size, e, NULL);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    unsigned char* data = malloc(data_size);
    RAND_bytes(data, data_size);

    RSAArg arg = { .key_size = key_size, .data_size = data_size, .data = data, .pkey = pkey };
    time_total_delta(verify_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
    BN_free(e);
}