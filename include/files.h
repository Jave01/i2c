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
#define MAX_VAL_LEN         60                               //!< Maximum password length
#define MAX_DB_NAME_LEN     31                               //!< Maximum file name length
#define MAX_LINE_LEN        MAX_KEY_LEN + MAX_VAL_LEN + 2    //!< Key + Value + ':' + '\n'


/**********************************************************************************************
 * Types
 **********************************************************************************************/
typedef struct pw_list
{
    char* filename;     //!< Name of password file
    FILE* file;         //!< File pointer to the original file
    char* master_pw;    //!< Master password from this file
    int entry_count;    //!< Number of entries in pw file including master
}pw_list_t;


/**********************************************************************************************
 * Function Headers
 **********************************************************************************************/
int get_entry_count(pw_list_t *pwList);
char* get_entry(pw_list_t *pwList, char* str, char* key);
bool set_entry(pw_list_t* pw_list, char* key, char* val);
void set_master_pw(pw_list_t *pwList, char* new_pw);
bool check_master_pw(pw_list_t *pwList, char *master_pw);


#endif //PW_MANAGER_FILES_H
