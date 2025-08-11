#ifndef ECDSA_BENCH_H
#define ECDSA_BENCH_H
#include "timing.h"
#include <openssl/evp.h>

// Structure to hold ECDSA benchmark functions
typedef struct {
    const char* curve_name; // ECDSA curve name (e.g., "prime256v1")
    int curve_nid;          // OpenSSL curve NID (e.g., NID_X9_62_prime256v1)
    const EVP_MD* digest;   // Digest algorithm (e.g., EVP_sha256())
    int data_size;          // Size of data to sign/verify in bytes
    unsigned char* data;    // Data to be signed or verified
    EVP_PKEY* pkey;         // EVP key for signing/verification
} ECDSAArg;

void bench_ecdsa_keygen(const char* curve_name, int iterations, BenchmarkResult* result);
void bench_ecdsa_sign(const char* curve_name, const EVP_MD* digest, int data_size, int iterations, BenchmarkResult* result);
void bench_ecdsa_verify(const char* curve_name, const EVP_MD* digest, int data_size, int iterations, BenchmarkResult* result);

#endif // ECDSA_BENCH_H