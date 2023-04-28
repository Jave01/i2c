/*
 * Filename: password.c
 * Author: David Jäggli
 * Date: 28.3.2023
 * Description: Utility messing with passwords including specifically copying to clipboard and generating passwords.
 *
 */

/**********************************************************************************************
 * Includes
 **********************************************************************************************/
/* external libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <sodium.h>

/* custom imports */
#include "password.h"
#include "files.h"

/**
 * WIP
 * @param dest
 */
void generate_passwd(char *dest, const passwordGenComplexity complexity, int pw_len)
{
    if(pw_len < 1 || pw_len > MAX_VAL_LEN){
        printf("Password length not valid\n");
        return;
    }
    char charset[MAX_PASSWORD_CHARSET_LEN] = {0};

    switch (complexity) {
        case LOW:
            strcpy(charset, PASSWORD_COMPLEXITY_LOW_CHARSET);
            break;
        case MEDIUM:
            strcpy(charset, PASSWORD_COMPLEXITY_MEDIUM_CHARSET);
            break;
        case HIGH:
            strcpy(charset, PASSWORD_COMPLEXITY_HIGH_CHARSET);
            break;
        default:
            printf("invalid password generation complexity\n");
            break;
    }
    const int charset_len = strlen(charset);
    int char_index;

    for (int i = 0; i < pw_len; ++i) {
        char_index = rand() % charset_len;
        dest[i] = charset[char_index];
    }

    printf("generated password: %s\n", dest);
}


/**
 * WIP
 * @param str
 */
void copy_to_clipboard(const char *str)
{

}
