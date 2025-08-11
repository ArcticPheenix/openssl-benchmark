#ifndef ED25519_BENCH_H
#define ED25519_BENCH_H
#include "timing.h"
#include <openssl/evp.h>

// Structure to hold Ed25519 benchmark functions
typedef struct {
    int data_size; // Size of data to sign/verify in bytes
    unsigned char* data; // Data to be signed or verified
    EVP_PKEY* pkey; // EVP key for signing/verification
} Ed25519Arg;

void bench_ed25519_keygen(int iterations, BenchmarkResult* result);
void bench_ed25519_sign(int data_size, int iterations, BenchmarkResult* result);
void bench_ed25519_verify(int data_size, int iterations, BenchmarkResult* result);

#endif // ED25519_BENCH_H