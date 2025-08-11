#include "pqc_bench.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

static int get_pqc_signature_size(const char* algo_name) {
    if (strcmp(algo_name, "ML-DSA-44") == 0) return 2420;
    if (strcmp(algo_name, "ML-DSA-65") == 0) return 3293;
    if (strcmp(algo_name, "ML-DSA-87") == 0) return 4627;
    if (strcmp(algo_name, "SLH-DSA-SHA2-128s") == 0) return 7856;
    if (strcmp(algo_name, "SLH-DSA-SHA2-128f") == 0) return 4960;
    if (strcmp(algo_name, "SLH-DSA-SHA2-192s") == 0) return 16224;
    if (strcmp(algo_name, "SLH-DSA-SHA2-192f") == 0) return 10208;
    if (strcmp(algo_name, "SLH-DSA-SHA2-256s") == 0) return 29792;
    if (strcmp(algo_name, "SLH-DSA-SHA2-256f") == 0) return 18816;
    if (strcmp(algo_name, "SLH-DSA-SHAKE-128s") == 0) return 7888;
    if (strcmp(algo_name, "SLH-DSA-SHAKE-128f") == 0) return 4984;
    if (strcmp(algo_name, "SLH-DSA-SHAKE-192s") == 0) return 16240;
    if (strcmp(algo_name, "SLH-DSA-SHAKE-192f") == 0) return 10232;
    if (strcmp(algo_name, "SLH-DSA-SHAKE-256s") == 0) return 29824;
    if (strcmp(algo_name, "SLH-DSA-SHAKE-256f") == 0) return 18848;
    return 0;
}

static int is_valid_pqc_algo(const char* algo_name) {
    return (strcmp(algo_name, "ML-DSA-44") == 0 ||
            strcmp(algo_name, "ML-DSA-65") == 0 ||
            strcmp(algo_name, "ML-DSA-87") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHA2-128s") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHA2-128f") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHA2-192s") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHA2-192f") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHA2-256s") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHA2-256f") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHAKE-128s") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHAKE-128f") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHAKE-192s") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHAKE-192f") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHAKE-256s") == 0 ||
            strcmp(algo_name, "SLH-DSA-SHAKE-256f") == 0);
}

static void pqc_keygen_func(void* arg) {
    PQCArg* pqc_arg = (PQCArg*)arg;
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, pqc_arg->algo_name);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to generate PQC key for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    EVP_PKEY_free(pkey);
}

void bench_pqc_keygen(const char* algo_name, int iterations, BenchmarkResult* result) {
    if (!is_valid_pqc_algo(algo_name)) {
        fprintf(stderr, "Invalid PQC algorithm: %s\n", algo_name);
        return;
    }
    PQCArg arg = { .algo_name = algo_name };
    time_per_iteration(pqc_keygen_func, &arg, iterations, result);
}

static void pqc_sign_func(void* arg) {
    PQCArg* pqc_arg = (PQCArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    size_t sig_len;
    unsigned char* sig = malloc(get_pqc_signature_size(pqc_arg->algo_name));
    if (!sig) {
        fprintf(stderr, "Failed to allocate signature buffer for %s\n", pqc_arg->algo_name);
        EVP_MD_CTX_free(ctx);
        return;
    }
    // Seed RNG explicitly
    unsigned char seed[32];
    if (RAND_bytes(seed, 32) <= 0) {
        fprintf(stderr, "RAND_bytes failed for seeding in %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    RAND_seed(seed, 32);
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pqc_arg->pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestSign(ctx, sig, &sig_len, pqc_arg->data, pqc_arg->data_size) <= 0) {
        fprintf(stderr, "EVP_DigestSign failed for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    free(sig);
    EVP_MD_CTX_free(ctx);
}

void bench_pqc_sign(const char* algo_name, int data_size, int iterations, BenchmarkResult* result) {
    if (!is_valid_pqc_algo(algo_name)) {
        fprintf(stderr, "Invalid PQC algorithm: %s\n", algo_name);
        return;
    }
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, algo_name);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to generate PQC key for %s\n", algo_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    unsigned char* data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        return;
    }
    if (RAND_bytes(data, data_size) <= 0) {
        fprintf(stderr, "RAND_bytes failed for %s\n", algo_name);
        ERR_print_errors_fp(stderr);
        free(data);
        EVP_PKEY_free(pkey);
        return;
    }

    PQCArg arg = { .algo_name = algo_name, .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(pqc_sign_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}

static void pqc_verify_func(void* arg) {
    PQCArg* pqc_arg = (PQCArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    size_t sig_len;
    unsigned char* sig = malloc(get_pqc_signature_size(pqc_arg->algo_name));
    if (!sig) {
        fprintf(stderr, "Failed to allocate signature buffer for %s\n", pqc_arg->algo_name);
        EVP_MD_CTX_free(ctx);
        return;
    }
    // Seed RNG explicitly
    unsigned char seed[32];
    if (RAND_bytes(seed, 32) <= 0) {
        fprintf(stderr, "RAND_bytes failed for seeding in %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    RAND_seed(seed, 32);
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pqc_arg->pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed for %s in verify\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestSign(ctx, sig, &sig_len, pqc_arg->data, pqc_arg->data_size) <= 0) {
        fprintf(stderr, "EVP_DigestSign failed for %s in verify\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pqc_arg->pkey) <= 0) {
        fprintf(stderr, "EVP_DigestVerifyInit failed for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestVerify(ctx, sig, sig_len, pqc_arg->data, pqc_arg->data_size) <= 0) {
        fprintf(stderr, "EVP_DigestVerify failed for %s\n", pqc_arg->algo_name);
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        return;
    }
    free(sig);
    EVP_MD_CTX_free(ctx);
}

void bench_pqc_verify(const char* algo_name, int data_size, int iterations, BenchmarkResult* result) {
    if (!is_valid_pqc_algo(algo_name)) {
        fprintf(stderr, "Invalid PQC algorithm: %s\n", algo_name);
        return;
    }
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, algo_name);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to generate PQC key for %s\n", algo_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    unsigned char* data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_free(pkey);
        return;
    }
    if (RAND_bytes(data, data_size) <= 0) {
        fprintf(stderr, "RAND_bytes failed for %s\n", algo_name);
        ERR_print_errors_fp(stderr);
        free(data);
        EVP_PKEY_free(pkey);
        return;
    }

    PQCArg arg = { .algo_name = algo_name, .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(pqc_verify_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}