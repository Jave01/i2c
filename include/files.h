//
// Created by dave on 14.03.23.
//

#ifndef PW_MANAGER_FILES_H
#define PW_MANAGER_FILES_H

/**********************************************************************************************
 * Includes
 **********************************************************************************************/
#include <stdio.h>
#include <stdbool.h>


/**********************************************************************************************
 * Constants
 **********************************************************************************************/
#define MAX_KEY_LEN         30                               //!< Maximum entry key length
#define MAX_VAL_LEN         50                               //!< Maximum password length
#define MAX_DB_NAME_LEN     31                               //!< Maximum file name length
#define MAX_LINE_LEN        82    //!< Key + Value + ':' + '\n'
#define SHA256_STR_LEN      2 * SHA_DIGEST_LENGTH

/**********************************************************************************************
 * Types
 **********************************************************************************************/
typedef struct pw_list
{
    unsigned char* filename;       //!< Name of password file
    FILE* file;                    //!< File pointer to the original file
    unsigned char* master_pw;      //!< Master password from this file
    int entry_count;               //!< Number of entries in pw file including master
    unsigned char * content;       //!< All unencrypted entries
}pw_list_t;


/**********************************************************************************************
 * Function Headers
 **********************************************************************************************/
int get_entry_count(const pw_list_t *pwList);
long get_entry(pw_list_t *pwList, unsigned char *str, const unsigned char *key);
bool set_entry(pw_list_t* pw_list, const unsigned char *key, const unsigned char *val);
void save_master_pw(pw_list_t *pwList, char *new_pw);
bool check_master_pw(pw_list_t *pwList, const char *master_pw);


#endif //PW_MANAGER_FILES_H
