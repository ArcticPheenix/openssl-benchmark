#ifndef PQC_BENCH_H
#define PQC_BENCH_H
#include "timing.h"
#include <openssl/evp.h>

// Structure to hold PQC (ML-DSA, SLH-DSA) benchmark functions
typedef struct {
    const char* algo_name; // PQC algorithm name (e.g., ML-DSA-44)
    int data_size; // Size of data to sign/verify in bytes
    unsigned char* data; // Data to be signed or verified
    EVP_PKEY* pkey; // EVP key for signing/verification
} PQCArg;

void bench_pqc_keygen(const char* algo_name, int iterations, BenchmarkResult* result);
void bench_pqc_sign(const char* algo_name, int data_size, int iterations, BenchmarkResult* result);
void bench_pqc_verify(const char* algo_name, int data_size, int iterations, BenchmarkResult* result);

#endif // PQC_BENCH_H