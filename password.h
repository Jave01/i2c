//
// Created by dave on 28.03.23.
//

#ifndef PW_MANAGER_PASSWORD_H
#define PW_MANAGER_PASSWORD_H

/**********************************************************************************************
 * Includes
 **********************************************************************************************/
#include <stdlib.h>
#include <time.h>
#include <string.h>

/**********************************************************************************************
 * Contants
 **********************************************************************************************/
#define PASSWORD_COMPLEXITY_LOW_CHARSET         "abcdefghijklmnopqrstuvwxyz1234567890"
#define PASSWORD_COMPLEXITY_MEDIUM_CHARSET      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
#define PASSWORD_COMPLEXITY_HIGH_CHARSET        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.,;-_+*%&=+"
#define MAX_PASSWORD_CHARSET_LEN                75

/**********************************************************************************************
 * Types
 **********************************************************************************************/
typedef enum PasswordGenComplexity{
    LOW,
    MEDIUM,
    HIGH
}passwordGenComplexity;

/**********************************************************************************************
 * Public functions
 **********************************************************************************************/
void generate_passwd(char *dest, const passwordGenComplexity complexity, int pw_len);
void copy_to_clipboard(const char *str);


#endif //PW_MANAGER_PASSWORD_H
