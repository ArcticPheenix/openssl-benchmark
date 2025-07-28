#ifndef RSA_BENCH_H
#define RSA_BENCH_H
#include "timing.h"
#include <openssl/evp.h>

// Structure to hold RSA benchmark functions
typedef struct {
    int key_size; // RSA key size in bits
    int data_size; // Size of data to sign/verify in bytes
    unsigned char* data; // Data to be signed or verified
    EVP_PKEY* pkey; // EVP key for signing/verification
} RSAArg;

void bench_keygen(int key_size, int iterations, BenchmarkResult* result);
void bench_sign(int key_size, int data_size, int iterations, BenchmarkResult* result);
void bench_verify(int key_size, int data_size, int iterations, BenchmarkResult* result);

#endif // RSA_BENCH_H