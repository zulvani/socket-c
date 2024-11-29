#include <openssl/evp.h>
#include <stdio.h>

int main() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        printf("EVP_CIPHER_CTX_new: Success\n");
        EVP_CIPHER_CTX_free(ctx);
    } else {
        printf("EVP_CIPHER_CTX_new: Failed\n");
    }
    return 0;
}
