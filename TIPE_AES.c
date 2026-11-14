#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <time.h>

#define BLOCK_SIZE 16

void handleErrors(const char *msg) {
    fprintf(stderr, "Erreur : %s\n", msg);
    exit(EXIT_FAILURE);
}

void generate_random_string(char *str, int n) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "0123456789"
                           "!@#$%^&*()-_=+[]{};:,.<>?/";
    int charset_size = sizeof(charset) - 1;

    unsigned char random_bytes[n];
    if (!RAND_bytes(random_bytes, n))
        handleErrors("Erreur génération bytes aléatoires");

    for (int i = 0; i < n; ++i) {
        str[i] = charset[random_bytes[i] % charset_size];
    }
    str[n] = '\0';
}

int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx) handleErrors("Échec EVP_CIPHER_CTX_new");
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors("Échec EncryptInit");
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("Échec EncryptUpdate");
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("Échec EncryptFinal");
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (!ctx) handleErrors("Échec EVP_CIPHER_CTX_new");
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors("Échec DecryptInit");
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("Échec DecryptUpdate");
    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors("Échec DecryptFinal");
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

double get_elapsed_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

int main() {
    const int PLAINTEXT_LEN = 500000;

    unsigned char key[16] = "YXU3=[0xm4PV7Q0@";
    unsigned char iv[BLOCK_SIZE];

    char *plaintext = malloc(PLAINTEXT_LEN + 1);
    unsigned char *ciphertext = malloc(PLAINTEXT_LEN + BLOCK_SIZE);
    unsigned char *decryptedtext = malloc(PLAINTEXT_LEN + BLOCK_SIZE + 1);

    if (!plaintext || !ciphertext || !decryptedtext) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        return EXIT_FAILURE;
    }

    if (!RAND_bytes(iv, BLOCK_SIZE))
        handleErrors("Erreur de génération de l'IV");

    generate_random_string(plaintext, PLAINTEXT_LEN);

    struct timespec start_total, end_total;
    struct timespec start_enc, end_enc;
    struct timespec start_dec, end_dec;

    clock_gettime(CLOCK_MONOTONIC, &start_total);

    clock_gettime(CLOCK_MONOTONIC, &start_enc);
    int ciphertext_len = aes_encrypt((unsigned char *)plaintext, PLAINTEXT_LEN, key, iv, ciphertext);
    clock_gettime(CLOCK_MONOTONIC, &end_enc);

    clock_gettime(CLOCK_MONOTONIC, &start_dec);
    int decrypted_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
    clock_gettime(CLOCK_MONOTONIC, &end_dec);

    clock_gettime(CLOCK_MONOTONIC, &end_total);

    decryptedtext[decrypted_len] = '\0';

    double time_enc_ms = get_elapsed_ms(start_enc, end_enc);
    double time_dec_ms = get_elapsed_ms(start_dec, end_dec);
    double time_total_ms = get_elapsed_ms(start_total, end_total);

    printf("Temps chiffrement    : %.6f ms\n", time_enc_ms);
    printf("Temps déchiffrement  : %.6f ms\n", time_dec_ms);
    printf("Temps total          : %.6f ms\n", time_total_ms);

    if (decrypted_len == PLAINTEXT_LEN && strcmp(plaintext, (char *)decryptedtext) == 0) {
        printf("Déchiffrement correct\n");
    } else {
        printf("Déchiffrement incorrect\n");
    }

    free(plaintext);
    free(ciphertext);
    free(decryptedtext);

    return 0;
}
