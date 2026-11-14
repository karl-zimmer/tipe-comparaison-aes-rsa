#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define RSA_KEY_BITS 2048
#define RSA_KEY_BYTES (RSA_KEY_BITS / 8)
#define MAX_PLAINTEXT_LEN (RSA_KEY_BYTES - 42)  // Pour RSA-OAEP overhead (environ 42 bytes)

// Calcul du temps écoulé en milli-secondes
double get_elapsed_time_ms(struct timespec start, struct timespec end) {
    return ((end.tv_sec - start.tv_sec) * 1000.0) + ((end.tv_nsec - start.tv_nsec) / 1e6);
}


// Génère une chaîne aléatoire de taille n, caractères dans charset
void generate_random_string(char *str, int n) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/";
    int charset_size = sizeof(charset) - 1;
    unsigned char buf[n];
    if (RAND_bytes(buf, n) != 1) {
        fprintf(stderr, "Erreur génération nombre aléatoire cryptographique\n");
        exit(1);
    }
    for (int i = 0; i < n; ++i) {
        str[i] = charset[buf[i] % charset_size];
    }
    str[n] = '\0';
}

// Génération d'une clé RSA 2048 bits avec EVP_PKEY
EVP_PKEY* generate_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) {
        fprintf(stderr, "Erreur création contexte EVP_PKEY_CTX\n");
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Erreur initialisation keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) {
        fprintf(stderr, "Erreur réglage taille clé RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Erreur génération clé RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// Chiffrement avec RSA-OAEP via EVP_PKEY
int rsa_encrypt(EVP_PKEY *pkey, unsigned char *plaintext, size_t plaintext_len,
                unsigned char *ciphertext, size_t *ciphertext_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Erreur création contexte chiffrement\n");
        return 0;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Erreur init chiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "Erreur réglage padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    // Obtenir la taille du buffer nécessaire
    if (EVP_PKEY_encrypt(ctx, NULL, ciphertext_len, plaintext, plaintext_len) <= 0) {
        fprintf(stderr, "Erreur calcul taille buffer ciphertext\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len) <= 0) {
        fprintf(stderr, "Erreur chiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// Déchiffrement avec RSA-OAEP via EVP_PKEY
int rsa_decrypt(EVP_PKEY *pkey, unsigned char *ciphertext, size_t ciphertext_len,
                unsigned char *plaintext, size_t *plaintext_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        fprintf(stderr, "Erreur création contexte déchiffrement\n");
        return 0;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "Erreur init déchiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "Erreur réglage padding OAEP\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    // Obtenir taille buffer nécessaire
    if (EVP_PKEY_decrypt(ctx, NULL, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "Erreur calcul taille buffer plaintext\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_decrypt(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len) <= 0) {
        fprintf(stderr, "Erreur déchiffrement\n");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int main() {
    struct timespec start_total, end_total;
    clock_gettime(CLOCK_MONOTONIC, &start_total);

    // Génération clé RSA
    struct timespec start_keys, end_keys;
    clock_gettime(CLOCK_MONOTONIC, &start_keys);
    EVP_PKEY *pkey = generate_rsa_key();
    if (!pkey) {
        fprintf(stderr, "Erreur génération clé RSA\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_keys);

    // Message aléatoire
    int len = 50000;
    char *message = malloc(len + 1);
    if (!message) {
        fprintf(stderr, "Erreur malloc message\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    generate_random_string(message, len);

    // Chiffrement
    struct timespec start_enc, end_enc;
    clock_gettime(CLOCK_MONOTONIC, &start_enc);

    int nb_blocks = (len + MAX_PLAINTEXT_LEN - 1) / MAX_PLAINTEXT_LEN;
    unsigned char *encrypted = malloc(nb_blocks * RSA_KEY_BYTES);
    if (!encrypted) {
        fprintf(stderr, "Erreur malloc encrypted\n");
        free(message);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t ciphertext_len;
    int pos_enc = 0;
    for (int i = 0; i < nb_blocks; i++) {
        int chunk_size = (i == nb_blocks - 1) ? (len - i * MAX_PLAINTEXT_LEN) : MAX_PLAINTEXT_LEN;
        ciphertext_len = RSA_KEY_BYTES;

        if (!rsa_encrypt(pkey,
                         (unsigned char *)(message + i * MAX_PLAINTEXT_LEN),
                         chunk_size,
                         encrypted + pos_enc,
                         &ciphertext_len)) {
            fprintf(stderr, "Erreur chiffrement bloc %d\n", i);
            free(encrypted);
            free(message);
            EVP_PKEY_free(pkey);
            return 1;
        }
        pos_enc += ciphertext_len;
    }
    clock_gettime(CLOCK_MONOTONIC, &end_enc);

    // Déchiffrement
    struct timespec start_dec, end_dec;
    clock_gettime(CLOCK_MONOTONIC, &start_dec);

    unsigned char *decrypted = malloc(len + 1);  // max taille plaintext totale
    if (!decrypted) {
        fprintf(stderr, "Erreur malloc decrypted\n");
        free(encrypted);
        free(message);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t plaintext_len;
    int pos_dec = 0;
    int offset_enc = 0;
    for (int i = 0; i < nb_blocks; i++) {
        size_t current_cipher_len = RSA_KEY_BYTES;

        if (!rsa_decrypt(pkey,
                         encrypted + offset_enc,
                         current_cipher_len,
                         decrypted + pos_dec,
                         &plaintext_len)) {
            fprintf(stderr, "Erreur déchiffrement bloc %d\n", i);
            free(decrypted);
            free(encrypted);
            free(message);
            EVP_PKEY_free(pkey);
            return 1;
        }
        pos_dec += plaintext_len;
        offset_enc += current_cipher_len;
    }
    decrypted[pos_dec] = '\0';
    clock_gettime(CLOCK_MONOTONIC, &end_dec);

    clock_gettime(CLOCK_MONOTONIC, &end_total);

    // Affichage temps
    printf("\n--- Temps d'exécution ---\n");
    printf("Génération des clés : %.3f ms\n", get_elapsed_time_ms(start_keys, end_keys));
    printf("Chiffrement         : %.3f ms\n", get_elapsed_time_ms(start_enc, end_enc));
    printf("Déchiffrement       : %.3f ms\n", get_elapsed_time_ms(start_dec, end_dec));
    printf("Temps total         : %.3f ms\n", get_elapsed_time_ms(start_total, end_total));


    // Vérification
    if (strncmp(message, (char*)decrypted, len) == 0) {
        printf("Déchiffrement correct\n");
    } else {
        printf("Erreur : déchiffrement incorrect\n");
    }

    // Libération mémoire
    free(decrypted);
    free(encrypted);
    free(message);
    EVP_PKEY_free(pkey);

    return 0;
}
