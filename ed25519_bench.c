#include "ed25519_bench.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

static void ed25519_keygen_func(void* arg) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        return;
    }
    EVP_PKEY_free(pkey);
}

void bench_ed25519_keygen(int iterations, BenchmarkResult* result) {
    Ed25519Arg arg = {0};
    time_per_iteration(ed25519_keygen_func, &arg, iterations, result);
}

static void ed25519_sign_func(void* arg) {
    Ed25519Arg* ed25519_arg = (Ed25519Arg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX for Ed25519\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    size_t sig_len;
    unsigned char sig[64]; // Ed25519 signatures are 64 bytes
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed25519_arg->pkey) <= 0 ||
        EVP_DigestSignUpdate(ctx, ed25519_arg->data, ed25519_arg->data_size) <= 0 ||
        EVP_DigestSignFinal(ctx, NULL, &sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestSign setup failed for Ed25519\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (sig_len > 64) {
        fprintf(stderr, "Signature size %zu exceeds 64 bytes for Ed25519\n", sig_len);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal failed for Ed25519\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    EVP_MD_CTX_free(ctx);
}

void bench_ed25519_sign(int data_size, int iterations, BenchmarkResult* result) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        return;
    }
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_ED25519) {
        fprintf(stderr, "Invalid Ed25519 key\n");
        EVP_PKEY_free(pkey);
        return;
    }
    unsigned char* data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        return;
    }
    if (RAND_bytes(data, data_size) <= 0) {
        fprintf(stderr, "RAND_bytes failed for Ed25519\n");
        ERR_print_errors_fp(stderr);
        free(data);
        EVP_PKEY_free(pkey);
        return;
    }

    Ed25519Arg arg = { .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(ed25519_sign_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}

static void ed25519_verify_func(void* arg) {
    Ed25519Arg* ed25519_arg = (Ed25519Arg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX for Ed25519\n");
        ERR_print_errors_fp(stderr);
        return;
    }
    size_t sig_len;
    unsigned char sig[64];
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, ed25519_arg->pkey) <= 0 ||
        EVP_DigestSignUpdate(ctx, ed25519_arg->data, ed25519_arg->data_size) <= 0 ||
        EVP_DigestSignFinal(ctx, NULL, &sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestSign setup failed for Ed25519 in verify\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (sig_len > 64) {
        fprintf(stderr, "Signature size %zu exceeds 64 bytes for Ed25519 in verify\n", sig_len);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestSignFinal failed for Ed25519 in verify\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, ed25519_arg->pkey) <= 0 ||
        EVP_DigestVerifyUpdate(ctx, ed25519_arg->data, ed25519_arg->data_size) <= 0 ||
        EVP_DigestVerifyFinal(ctx, sig, sig_len) <= 0) {
        fprintf(stderr, "EVP_DigestVerify failed for Ed25519\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    EVP_MD_CTX_free(ctx);
}

void bench_ed25519_verify(int data_size, int iterations, BenchmarkResult* result) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    if (pkey == NULL) {
        ERR_print_errors_fp(stderr);
        return;
    }
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_ED25519) {
        fprintf(stderr, "Invalid Ed25519 key\n");
        EVP_PKEY_free(pkey);
        return;
    }
    unsigned char* data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        return;
    }
    if (RAND_bytes(data, data_size) <= 0) {
        fprintf(stderr, "RAND_bytes failed for Ed25519\n");
        ERR_print_errors_fp(stderr);
        free(data);
        EVP_PKEY_free(pkey);
        return;
    }

    Ed25519Arg arg = { .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(ed25519_verify_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}