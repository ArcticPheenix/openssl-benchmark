#include <stdio.h>
#include <openssl/evp.h>

int main(int arc, char *argv[]) {
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    return 0;
}