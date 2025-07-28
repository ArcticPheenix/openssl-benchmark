#include "rsa_bench.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

static void keygen_func(void* arg) {
    RSAArg* rsa_arg = (RSAArg*)arg;
    EVP_PKEY* pkey = EVP_RSA_gen(rsa_arg->key_size);
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        return;
    }
    EVP_PKEY_free(pkey);
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
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_arg->pkey) <= 0 ||
        EVP_DigestSign(ctx, sig, &sig_len, rsa_arg->data, rsa_arg->data_size) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    EVP_MD_CTX_free(ctx);
}

void bench_sign(int key_size, int data_size, int iterations, BenchmarkResult* result) {
    // Setup key and data
    EVP_PKEY* pkey = EVP_RSA_gen(key_size);
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        return;
    }
    unsigned char* data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        return;
    }
    RAND_bytes(data, data_size);

    RSAArg arg = { .key_size = key_size, .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(sign_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}

static void verify_func(void* arg) {
    RSAArg* rsa_arg = (RSAArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t sig_len;
    unsigned char sig[512];
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, rsa_arg->pkey) <= 0 ||
        EVP_DigestSign(ctx, sig, &sig_len, rsa_arg->data, rsa_arg->data_size) <= 0 ||
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, rsa_arg->pkey) <= 0 ||
        EVP_DigestVerify(ctx, sig, sig_len, rsa_arg->data, rsa_arg->data_size) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    EVP_MD_CTX_free(ctx);
}

void bench_verify(int key_size, int data_size, int iterations, BenchmarkResult* result) {
    // Setup key and data
    EVP_PKEY* pkey = EVP_RSA_gen(key_size);
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        return;
    }
    unsigned char* data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        return;
    }
    RAND_bytes(data, data_size);

    RSAArg arg = { .key_size = key_size, .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(verify_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}