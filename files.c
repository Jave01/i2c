/*
 * Filename: files.c
 * Author: David Jäggli
 * Date: 20.3.2023
 * Description: Standard functions for reading, editing and data collecting of
 *              password manager files.
 */


/**********************************************************************************************
 * Local includes
 **********************************************************************************************/
/* external libraries */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>

/* custom imports */
#include "files.h"


/**********************************************************************************************
 * Function definitions
 **********************************************************************************************/
/**
 * Returns the number of lines which aren't empty.
 * @param pwList pointer to pw_file object
 * @return the number of lines
*/
int get_entry_count(pw_list_t *pwList){
    int lines=0;

    rewind(pwList->file);

    char buffer[MAX_LINE_LEN] = {0};
    while (fgets(buffer, MAX_LINE_LEN, pwList->file) != NULL) {
        if (strcmp(buffer, "\n") != 0) // check if line is empty
        {
            lines++;
        }
    }

    return lines;
}


/** Returns the value of the entry based on the key.
 * Writes the string into the str variable and returns the pointer to the value.
 * @param pwList  pointer to pw_file object
 * @param str destination where the value gets written into
 * @param key key to search for in the file
 * @return pointer to the value string
*/
char* get_entry(pw_list_t *pwList, char* str, char* key){
    int range = get_entry_count(pwList);

    if (range < 1)
    {
        printf("Not enough entries (%d)", range);
        return NULL;
    }

    rewind(pwList->file);
    char c;
    for (int i = 0; i < range; i++)
    {
        for (int j = 0; j <= strlen(key); j++)
        {
            c = fgetc(pwList->file);
            if (c != key[j])
            {
                if (c == ':'){
                    return fgets(str, MAX_VAL_LEN, pwList->file);
                }
                else{
                    break;
                }
            }
        }
        while ((c = fgetc(pwList->file)) != '\n' && c != EOF);// go to next entry
    }
    rewind(pwList->file);
    return NULL;
}


/** Change or create an entry in pw list.
 * If the entry key exists, the value gets overwritten, if it doesn't a new one is created.
 * @param pw_list a pointer to pw_list struct
 * @param key the key of the entry
 * @param val the value of the entry
 * @return bool if the action was successful
*/
bool set_entry(pw_list_t* pw_list, char* key, char* val){
    if (strlen(key) > MAX_KEY_LEN || strlen(key) < 1){
        printf("Key size invalid (%ld/%d chars)\n", strlen(key), MAX_KEY_LEN);
        return false;
    } else if (strlen(val) > MAX_VAL_LEN){
        printf("Value size invalid (%ld/%d chars)\n", strlen(val), MAX_VAL_LEN);
        return false;
    }

    /* some variables for determining the (maybe) existing entry */
    char entry_value[MAX_LINE_LEN];
    char* entry_p = get_entry(pw_list, entry_value, key);

    /* create new entry_value if it doesn't exist */
    if (entry_p == NULL)
    {
        fclose(pw_list->file);
        pw_list->file = fopen(pw_list->filename, "a+");

        /* insert newline if there isn't one */
        fseek(pw_list->file, 0, SEEK_END); // seek to end of file
        if (ftell(pw_list->file) > 0) { // check if file is non-empty
            fseek(pw_list->file, -1, SEEK_END);
            char c = fgetc(pw_list->file);
            if (c != '\n') {
                fputc('\n', pw_list->file);
            }
        }

        /* add content */
        if (fputs(key, pw_list->file) == EOF ||
            fputc(':', pw_list->file) == EOF ||
            fputs(val, pw_list->file) == EOF) {
            perror("Error while writing to file");
        }

        fclose(pw_list->file);

        pw_list->file = fopen(pw_list->filename, "r+");
        pw_list->entry_count++;

        printf("added content successfully\n");

        return true;

    } else {
        /* If entry does exist, copy the file leading file content to a temp file,
         * insert the new data and append the remaining data. The original file will be
         * deleted and the temp file renamed to the original filename
        /* copy content */
        FILE* ftemp = fopen("temp.txt", "w");

        char c;
        while ((c = fgetc(pw_list->file)) != EOF)
        {
            fputc(c, ftemp);
        }
        fseek(pw_list->file, -1, SEEK_END);

        if (fgetc(pw_list->file) != '\n'){
            fputc('\n', ftemp);
        }

        /* replace old file */
        fclose(pw_list->file);
        remove(pw_list->filename);
        rename("temp.txt", pw_list->filename);

    }
    return true;
}


/** Check if entered string matches the master password saved in the file.
 * Uses SHA256 on the given string and compares it with the first string in the file
 * which should be the stored master password.
 * @param pwList a pointer to pw_list struct
 * @param master_pw the entered password in plain text
 * @return true if hashes match false otherwise
 */
bool check_master_pw(pw_list_t *pwList, char *master_pw) {
    rewind(pwList->file);
    /* --- read in and compare --- */
    // Read in the stored hash from the file
    unsigned char stored_hash[SHA256_DIGEST_LENGTH];

    char stored_hash_str[2 * SHA256_DIGEST_LENGTH + 1];
    fscanf(pwList->file, "%s", stored_hash_str);

    // Convert the stored hash from hexadecimal string to raw bytes
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sscanf(stored_hash_str + 2*i, "%2hhx", &stored_hash[i]);
    }

    // Compute the hash of the new string
    unsigned char new_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)master_pw, strlen(master_pw), new_hash);

    // Compare the two hashes
    if (memcmp(stored_hash, new_hash, SHA256_DIGEST_LENGTH) == 0) {
        return true;
    }else{
        return false;
    }
}


/** Save the new password as hash in the file.
 * The given string gets hashed with SHA256 and written at the beginning of the file, where
 * the master pw should be stored.
 * @param pwList a pointer to pw_list struct
 * @param new_pw the new password in plain text
 */
void save_master_pw(pw_list_t *pwList, char *new_pw) {
    strcpy(pwList->master_pw, new_pw);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pwList->master_pw, strlen(pwList->master_pw), hash);

    rewind(pwList->file);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(pwList->file, "%02x", hash[i]);
    }
}