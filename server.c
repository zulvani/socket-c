// Server side C program to demonstrate Socket programming with AES encryption
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
// #define AES_KEY_LENGTH 256
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
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    unsigned char buffer[1024] = {0};
    unsigned char decrypted[1024] = {0}; // Buffer for decrypted message

    // Plain text string for key and IV
    const char *key_str = "my_secret_key_1234567890abcdef";
    const char *iv_str = "my_initialization_vector";

    // Adjust to required lengths
    unsigned char key[AES_KEYLEN];
    unsigned char iv[AES_IVLEN];
    adjustKeyOrIV(key_str, key, AES_KEYLEN);
    adjustKeyOrIV(iv_str, iv, AES_IVLEN);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Attaching socket to port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind to port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    unsigned char decryptedtext[128];
    int ciphertext_len, decryptedtext_len;

    // Receive IV from client
    // read(new_socket, aes_iv, AES_BLOCK_SIZE);

    // Receive encrypted message
    valread = read(new_socket, buffer, 1024 - 1);
    
    // Decrypt the message
    // aes_decrypt(buffer, decrypted, aes_key, aes_iv);
    // printf("Decrypted message from client: %s\n", decrypted);

    printf("Plain text message from client: %s\n", buffer);

    decryptedtext_len = decrypt(buffer, strlen((char *)buffer), key, iv, decryptedtext);
    printf("Decrypted message from client: %s\n", decryptedtext);

    // Close sockets
    close(new_socket);
    close(server_fd);
    return 0;
}