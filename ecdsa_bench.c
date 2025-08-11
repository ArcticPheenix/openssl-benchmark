#include "ecdsa_bench.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <stdlib.h>
#include <string.h>

static int get_curve_nid(const char* curve_name) {
    if (strcmp(curve_name, "P-256") == 0) return NID_X9_62_prime256v1;
    if (strcmp(curve_name, "P-384") == 0) return NID_secp384r1;
    if (strcmp(curve_name, "P-521") == 0) return NID_secp521r1;
    return NID_undef;
}

static EVP_PKEY* generate_ecdsa_key(const char* curve_name) {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    EVP_PKEY* param_key = NULL;
    int nid = get_curve_nid(curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Invalid curve: %s\n", curve_name);
        return NULL;
    }

    // Create parameter generation context
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for EC (%s)\n", curve_name);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Initialize parameter generation and set curve
    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        fprintf(stderr, "Failed to initialize paramgen for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
        fprintf(stderr, "Failed to set curve %s for paramgen\n", curve_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    // Generate parameters
    if (EVP_PKEY_paramgen(pctx, &param_key) <= 0) {
        fprintf(stderr, "Failed to generate EC parameters for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    // Create key generation context
    pctx = EVP_PKEY_CTX_new(param_key, NULL);
    if (!pctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for keygen (%s)\n", curve_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(param_key);
        return NULL;
    }

    // Generate key
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Failed to initialize keygen for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(param_key);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate ECDSA key for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(param_key);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    // Verify key type and curve
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
        fprintf(stderr, "Generated key is not ECDSA for %s\n", curve_name);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(param_key);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    int key_bits = EVP_PKEY_get_bits(pkey);
    int expected_bits = (nid == NID_X9_62_prime256v1) ? 256 : (nid == NID_secp384r1) ? 384 : 521;
    if (key_bits != expected_bits) {
        fprintf(stderr, "Invalid key size for %s: got %d bits, expected %d\n", curve_name, key_bits, expected_bits);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(param_key);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    // Verify key can sign
    if (!EVP_PKEY_can_sign(pkey)) {
        fprintf(stderr, "Key for %s cannot be used for signing\n", curve_name);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(param_key);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_free(param_key);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static void ecdsa_keygen_func(void* arg) {
    ECDSAArg* ecdsa_arg = (ECDSAArg*)arg;
    EVP_PKEY* pkey = generate_ecdsa_key(ecdsa_arg->curve_name);
    if (pkey == NULL) {
        // Error already printed
        return;
    }
    EVP_PKEY_free(pkey);
}

void bench_ecdsa_keygen(const char* curve_name, int iterations, BenchmarkResult* result) {
    int nid = get_curve_nid(curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Invalid curve: %s\n", curve_name);
        return;
    }
    ECDSAArg arg = { .curve_name = curve_name, .curve_nid = nid };
    time_per_iteration(ecdsa_keygen_func, &arg, iterations, result);
}

static void ecdsa_sign_func(void* arg) {
    ECDSAArg* ecdsa_arg = (ECDSAArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX for %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    size_t sig_len;
    unsigned char sig[160]; // Sufficient for ECDSA (P-521 max ~132 bytes)
    // Seed RNG explicitly
    unsigned char seed[32];
    if (RAND_bytes(seed, 32) <= 0) {
        fprintf(stderr, "RAND_bytes failed for seeding in %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    RAND_seed(seed, 32);
    if (EVP_DigestSignInit(ctx, NULL, ecdsa_arg->digest, NULL, ecdsa_arg->pkey) <= 0) {
        fprintf(stderr, "EVP_DigestSignInit failed for %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestSign(ctx, sig, &sig_len, ecdsa_arg->data, ecdsa_arg->data_size) <= 0) {
        fprintf(stderr, "EVP_DigestSign failed for %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    EVP_MD_CTX_free(ctx);
}

void bench_ecdsa_sign(const char* curve_name, const EVP_MD* digest, int data_size, int iterations, BenchmarkResult* result) {
    int nid = get_curve_nid(curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Invalid curve: %s\n", curve_name);
        return;
    }
    EVP_PKEY* pkey = generate_ecdsa_key(curve_name);
    if (pkey == NULL) {
        // Error already printed
        return;
    }
    // Verify key
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
        fprintf(stderr, "Invalid ECDSA key for %s\n", curve_name);
        EVP_PKEY_free(pkey);
        return;
    }
    int key_bits = EVP_PKEY_get_bits(pkey);
    int expected_bits = (nid == NID_X9_62_prime256v1) ? 256 : (nid == NID_secp384r1) ? 384 : 521;
    if (key_bits != expected_bits) {
        fprintf(stderr, "Invalid key size for %s: got %d bits, expected %d\n", curve_name, key_bits, expected_bits);
        EVP_PKEY_free(pkey);
        return;
    }
    if (!EVP_PKEY_can_sign(pkey)) {
        fprintf(stderr, "Key for %s cannot be used for signing\n", curve_name);
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
        fprintf(stderr, "RAND_bytes failed for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        free(data);
        EVP_PKEY_free(pkey);
        return;
    }

    ECDSAArg arg = { .curve_name = curve_name, .curve_nid = nid, .digest = digest, .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(ecdsa_sign_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}

static void ecdsa_verify_func(void* arg) {
    ECDSAArg* ecdsa_arg = (ECDSAArg*)arg;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX for %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        return;
    }
    size_t sig_len;
    unsigned char sig[160];
    // Seed RNG explicitly
    unsigned char seed[32];
    if (RAND_bytes(seed, 32) <= 0) {
        fprintf(stderr, "RAND_bytes failed for seeding in %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    RAND_seed(seed, 32);
    if (EVP_DigestSignInit(ctx, NULL, ecdsa_arg->digest, NULL, ecdsa_arg->pkey) <= 0 ||
        EVP_DigestSign(ctx, sig, &sig_len, ecdsa_arg->data, ecdsa_arg->data_size) <= 0) {
        fprintf(stderr, "EVP_DigestSign failed for %s in verify setup\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    if (EVP_DigestVerifyInit(ctx, NULL, ecdsa_arg->digest, NULL, ecdsa_arg->pkey) <= 0 ||
        EVP_DigestVerify(ctx, sig, sig_len, ecdsa_arg->data, ecdsa_arg->data_size) <= 0) {
        fprintf(stderr, "EVP_DigestVerify failed for %s\n", ecdsa_arg->curve_name);
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return;
    }
    EVP_MD_CTX_free(ctx);
}

void bench_ecdsa_verify(const char* curve_name, const EVP_MD* digest, int data_size, int iterations, BenchmarkResult* result) {
    int nid = get_curve_nid(curve_name);
    if (nid == NID_undef) {
        fprintf(stderr, "Invalid curve: %s\n", curve_name);
        return;
    }
    EVP_PKEY* pkey = generate_ecdsa_key(curve_name);
    if (pkey == NULL) {
        // Error already printed
        return;
    }
    // Verify key
    if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) {
        fprintf(stderr, "Invalid ECDSA key for %s\n", curve_name);
        EVP_PKEY_free(pkey);
        return;
    }
    int key_bits = EVP_PKEY_get_bits(pkey);
    int expected_bits = (nid == NID_X9_62_prime256v1) ? 256 : (nid == NID_secp384r1) ? 384 : 521;
    if (key_bits != expected_bits) {
        fprintf(stderr, "Invalid key size for %s: got %d bits, expected %d\n", curve_name, key_bits, expected_bits);
        EVP_PKEY_free(pkey);
        return;
    }
    if (!EVP_PKEY_can_sign(pkey)) {
        fprintf(stderr, "Key for %s cannot be used for signing\n", curve_name);
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
        fprintf(stderr, "RAND_bytes failed for %s\n", curve_name);
        ERR_print_errors_fp(stderr);
        free(data);
        EVP_PKEY_free(pkey);
        return;
    }

    ECDSAArg arg = { .curve_name = curve_name, .curve_nid = nid, .digest = digest, .data_size = data_size, .data = data, .pkey = pkey };
    time_per_iteration(ecdsa_verify_func, &arg, iterations, result);

    free(data);
    EVP_PKEY_free(pkey);
}