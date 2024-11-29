#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEYLEN 32  // 256 bits
#define AES_IVLEN 16   // 128 bits

// Function to handle errors
void handleErrors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Encrypt function
int encrypt(const unsigned char *plaintext, int plaintext_len, 
            const unsigned char *key, const unsigned char *iv, 
            unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Failed to create context");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors("Failed to initialize encryption");

    int len, ciphertext_len;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("Failed to encrypt data");

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("Failed to finalize encryption");

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypt function
int decrypt(const unsigned char *ciphertext, int ciphertext_len, 
            const unsigned char *key, const unsigned char *iv, 
            unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors("Failed to create context");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors("Failed to initialize decryption");

    int len, plaintext_len;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("Failed to decrypt data");

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors("Failed to finalize decryption");

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main() {
    // Plaintext, key, and IV
    unsigned char *plaintext = (unsigned char *)"This is a secret message!";
    unsigned char key[AES_KEYLEN], iv[AES_IVLEN];

    // Generate random key and IV
    if (!RAND_bytes(key, sizeof(key))) handleErrors("Failed to generate key");
    if (!RAND_bytes(iv, sizeof(iv))) handleErrors("Failed to generate IV");

    printf("Key: ");
    for (int i = 0; i < AES_KEYLEN; i++) printf("%02x", key[i]);
    printf("\nIV: ");
    for (int i = 0; i < AES_IVLEN; i++) printf("%02x", iv[i]);
    printf("\n");

    // Allocate memory for ciphertext
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int ciphertext_len, decryptedtext_len;

    // Encrypt the plaintext
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    // Decrypt the ciphertext
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0'; // Null-terminate the decrypted string
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
