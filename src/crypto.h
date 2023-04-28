//
// Created by dave on 20.03.23.
//

#ifndef PW_MANAGER_CRYPTO_H
#define PW_MANAGER_CRYPTO_H
/**********************************************************************************************
 * Includes
 **********************************************************************************************/
/* external libraries */
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

/* custom libraries */
#include "files.h"

/**********************************************************************************************
 * Public function headers
 **********************************************************************************************/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx,
             EVP_CIPHER_CTX *d_ctx);

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);


#endif //PW_MANAGER_CRYPTO_H
