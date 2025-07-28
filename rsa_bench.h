#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

void bench_keygen(int key_size, int iterations);