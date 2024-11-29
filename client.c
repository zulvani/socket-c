#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
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

// Function to adjust string to required length
void adjustKeyOrIV(const char *input, unsigned char *output, int required_len) {
    int len = strlen(input);
    if (len >= required_len) {
        memcpy(output, input, required_len);  // Truncate if too long
    } else {
        memcpy(output, input, len);          // Copy full string
        memset(output + len, 0, required_len - len);  // Pad with zeros
    }
}

int main(int argc, char const *argv[]) {
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;

    // Plaintext message to be sent
    unsigned char *plaintext = (unsigned char *)"Hello I'm Agus Zulvani";
    unsigned char encrypted[1024] = {0}; // Buffer for encrypted message
    unsigned char decrypted[1024] = {0}; // Buffer for decrypted message

    // Plain text string for key and IV
    const char *key_str = "my_secret_key_1234567890abcdef";
    const char *iv_str = "my_initialization_vector";

    // Adjust to required lengths
    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_IVLEN];
    adjustKeyOrIV(key_str, key, AES_KEYLEN);
    adjustKeyOrIV(iv_str, iv, AES_IVLEN);

    // Initialize socket
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to server
    if ((status = connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Send IV to server
    // send(client_fd, aes_iv, AES_BLOCK_SIZE, 0);
    // send(client_fd, plaintext, AES_BLOCK_SIZE, 0);
    int ciphertext_len, decryptedtext_len;

    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, encrypted);
    
    // Send encrypted message
    send(client_fd, encrypted, strlen((const char *)plaintext) + ciphertext_len, 0);
    printf("Encrypted message sent\n");

    // Read server response
    valread = read(client_fd, encrypted, 1024 - 1);
    // aes_decrypt(encrypted, decrypted, aes_key, aes_iv);
    // printf("Decrypted response from server: %s\n", decrypted);

    // Close the connected socket
    close(client_fd);
    return 0;
}