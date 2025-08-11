#include "rsa_bench.h"
#include "ecdsa_bench.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void print_help(char* prog_name) {
    printf("Usage: %s [options]\nOptions:\n"
           "--help\tShow this\n"
           "--key-size N\tRSA key bits (default 2048)\n"
           "--curve STR\tECDSA curve (P-256, P-384, P-521)\n"
           "--iterations N\tRuns (default 100)\n"
           "--operation STR\trsa-keygen/rsa-sign/rsa-verify (RSA) or ecdsa-keygen/ecdsa-sign/ecdsa-verify (ECDSA)\n"
           "--data-size N\tBytes for sign/verify (default 1024)\n", prog_name);
}

int main(int argc, char* argv[]) {
    int key_size = 2048, iterations = 100, data_size = 1024;
    char* operation = NULL;
    char* curve = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--key-size") == 0 && i + 1 < argc) {
            key_size = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--curve") == 0 && i + 1 < argc) {
            curve = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            iterations = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "--operation") == 0 && i + 1 < argc) {
            operation = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--data-size") == 0 && i + 1 < argc) {
            data_size = atoi(argv[i + 1]);
            i++;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            print_help(argv[0]);
            return 1;
        }
    }

    if (!operation) {
        fprintf(stderr, "Missing --operation\n");
        print_help(argv[0]);
        return 1;
    }

    BenchmarkResult result = {0};
    if (strcmp(operation, "rsa-keygen") == 0) {
        bench_keygen(key_size, iterations, &result);
        printf("%s (%d-bit, %d iterations): Avg %.2f ms, Ops/s: %.2f, StdDev %.2f µs, Min %.2f ms, Max %.2f ms\n",
               operation, key_size, result.iterations, result.avg_time_ms, result.ops_per_sec,
               result.std_dev_us, result.min_time_ms, result.max_time_ms);
    } else if (strcmp(operation, "rsa-sign") == 0) {
        bench_sign(key_size, data_size, iterations, &result);
        printf("%s (%d-bit, %d iterations): Avg %.2f ms, Ops/s: %.2f, StdDev %.2f µs, Min %.2f ms, Max %.2f ms\n",
               operation, key_size, result.iterations, result.avg_time_ms, result.ops_per_sec,
               result.std_dev_us, result.min_time_ms, result.max_time_ms);
    } else if (strcmp(operation, "rsa-verify") == 0) {
        bench_verify(key_size, data_size, iterations, &result);
        printf("%s (%d-bit, %d iterations): Avg %.2f ms, Ops/s: %.2f, StdDev %.2f µs, Min %.2f ms, Max %.2f ms\n",
               operation, key_size, result.iterations, result.avg_time_ms, result.ops_per_sec,
               result.std_dev_us, result.min_time_ms, result.max_time_ms);
    } else if (strcmp(operation, "ecdsa-keygen") == 0) {
        if (!curve) {
            fprintf(stderr, "Missing --curve for ECDSA\n");
            print_help(argv[0]);
            return 1;
        }
        bench_ecdsa_keygen(curve, iterations, &result);
        printf("%s (%s, %d iterations): Avg %.2f ms, Ops/s: %.2f, StdDev %.2f µs, Min %.2f ms, Max %.2f ms\n",
               operation, curve, result.iterations, result.avg_time_ms, result.ops_per_sec,
               result.std_dev_us, result.min_time_ms, result.max_time_ms);
    } else if (strcmp(operation, "ecdsa-sign") == 0) {
        if (!curve) {
            fprintf(stderr, "Missing --curve for ECDSA\n");
            print_help(argv[0]);
            return 1;
        }
        const EVP_MD* digest = NULL;
        if (strcmp(curve, "P-256") == 0) digest = EVP_sha256();
        else if (strcmp(curve, "P-384") == 0) digest = EVP_sha384();
        else if (strcmp(curve, "P-521") == 0) digest = EVP_sha512();
        else {
            fprintf(stderr, "Invalid curve: %s\n", curve);
            return 1;
        }
        bench_ecdsa_sign(curve, digest, data_size, iterations, &result);
        printf("%s (%s, %d iterations): Avg %.2f ms, Ops/s: %.2f, StdDev %.2f µs, Min %.2f ms, Max %.2f ms\n",
               operation, curve, result.iterations, result.avg_time_ms, result.ops_per_sec,
               result.std_dev_us, result.min_time_ms, result.max_time_ms);
    } else if (strcmp(operation, "ecdsa-verify") == 0) {
        if (!curve) {
            fprintf(stderr, "Missing --curve for ECDSA\n");
            print_help(argv[0]);
            return 1;
        }
        const EVP_MD* digest = NULL;
        if (strcmp(curve, "P-256") == 0) digest = EVP_sha256();
        else if (strcmp(curve, "P-384") == 0) digest = EVP_sha384();
        else if (strcmp(curve, "P-521") == 0) digest = EVP_sha512();
        else {
            fprintf(stderr, "Invalid curve: %s\n", curve);
            return 1;
        }
        bench_ecdsa_verify(curve, digest, data_size, iterations, &result);
        printf("%s (%s, %d iterations): Avg %.2f ms, Ops/s: %.2f, StdDev %.2f µs, Min %.2f ms, Max %.2f ms\n",
               operation, curve, result.iterations, result.avg_time_ms, result.ops_per_sec,
               result.std_dev_us, result.min_time_ms, result.max_time_ms);
    } else {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        return 1;
    }

    return 0;
}