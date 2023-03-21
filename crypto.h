//
// Created by dave on 20.03.23.
//

#ifndef PW_MANAGER_CRYPTO_H
#define PW_MANAGER_CRYPTO_H
/**********************************************************************************************
 * Includes
 **********************************************************************************************/
#include <stdio.h>
#include <openssl/sha.h>
#include "files.h"

/**********************************************************************************************
 * Public function headers
 **********************************************************************************************/
void encrypt_file(pw_list_t pwList);
void decrypt_file(pw_list_t pwList);

#endif //PW_MANAGER_CRYPTO_H
