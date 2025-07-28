#include "rsa_bench.h"

void bench_keygen(int key_size, int iterations) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        if (RSA_generate_key_ex(rsa, key_size, bn, NULL) != 1) {
            fprintf(stderr, "Error generating RSA key\n");
            BN_free(bn);
            RSA_free(rsa);
            return;
        }
        BN_free(bn);
        RSA_free(rsa);
    }
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Time taken for RSA key generation (%d bits): %.2f seconds\n", key_size, time_spent);
}