/*
 * Filename: files.c
 * Author: David Jäggli
 * Date: 20.3.2023
 * Description: Functions for reading, editing and data collecting of
 *              password manager files.
 */


/**********************************************************************************************
 * Local includes
 **********************************************************************************************/
/* external libraries */
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <sodium.h>
#include <math.h>

/* custom imports */
#include "files.h"
#include "crypto.h"


/**********************************************************************************************
 * Function definitions
 **********************************************************************************************/
/**
 * Returns the number of lines which aren't empty.
 * @param pwList pointer to pw_file object
 * @return the number of lines
*/
int get_entry_count(const pw_list_t *pwList){
    int lines=0;

    for (size_t i = 0; i < strlen(pwList->entries); i++)
    {
        if (pwList->entries[i] == '\n')
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
 * @return offset in the pwList content string, -1 if not found
*/
long get_entry_value(const pw_list_t *pwList, unsigned char *str, const unsigned char *key){
    int range = get_entry_count(pwList);
    unsigned char* current_entry = pwList->entries;
    u_int8_t key_len = strlen(key);

    for (size_t i = 0; i < range; i++)
    {
        if(strncmp(current_entry, key, key_len)==0){
            if (current_entry[strlen(key)] == ':')
            {
                current_entry += key_len + 1;
                unsigned char* stop = (unsigned char*) strchr(current_entry, '\n');
                long val_size = stop - current_entry;
                strncpy(str, current_entry, val_size);
                str[val_size] = '\0';
                return current_entry - pwList->entries; // offset to value
            }
        }
        current_entry = strchr(current_entry, '\n') + 1;
    }
    
    return -1;
}


/** Change or create an entry in pw list.
 * If the entry key exists, the value gets overwritten, if it doesn't, a new one is created.
 * @param pwList a pointer to pwList struct
 * @param key the key of the entry
 * @param val the new value of the entry
 * @return bool if the action was successful
*/
bool set_entry(pw_list_t* pwList, const unsigned char *key, const unsigned char *val){
    
    if (strlen(key) > MAX_KEY_LEN || strlen(key) < 1){
        printf("Key size invalid (%ld/%d chars)\n", strlen(key), MAX_KEY_LEN);
        return false;
    } else if (strlen(val) > MAX_VAL_LEN){
        printf("Value size invalid (%ld/%d chars)\n", strlen(val), MAX_VAL_LEN);
        return false;
    }

    if (strlen(pwList->entries) + strlen(key) + strlen(val) + 2 > pwList->size * ENTRIES_BLOCK_SIZE){
        // if existing values + new values are bigger than the allocated size, the allocated size gets increased by ENTRIES_BLOCK_SIZE
        pwList->size++;
        unsigned char* new_ptr = realloc(pwList->entries, pwList->size * ENTRIES_BLOCK_SIZE * sizeof(unsigned char));
        if (new_ptr == NULL){
            perror("Error while reallocating memory");
            return false;
        }
        pwList->entries = new_ptr;
    }
    
    /* some variables for determining the (possibly) existing entry */
    unsigned char* entry_value = 0;
    entry_value = calloc(MAX_VAL_LEN, sizeof(unsigned char));
    if(entry_value == NULL){
        perror("Error while allocating memory");
        return false;
    }
    long entry_offset = get_entry_value(pwList, entry_value, key);
    
    // if the entry exists, the value gets overwritten
    // to do so, the other parts need to be copied to a new string
    if (entry_offset >= 0)
    {
        unsigned char* new_entries = calloc(pwList->size * ENTRIES_BLOCK_SIZE, sizeof(unsigned char));

        // copy values before old value
        strncpy(new_entries, pwList->entries, entry_offset);

        //  append new value
        strcat(new_entries, val);
        strcat(new_entries, "\n");

        // copy values after old value
        strcat(new_entries, pwList->entries + entry_offset + strlen(entry_value) + 1);

        strncpy(pwList->entries, new_entries, pwList->size * ENTRIES_BLOCK_SIZE);
    }
    else{
        // if the entry doesn't exist, it gets appended to the end of the string
        strcat(pwList->entries, key);
        strcat(pwList->entries, ":");
        strcat(pwList->entries, val);
        strcat(pwList->entries, "\n");
    }
    return true;
}


/** Check if entered string matches the master password saved in the file.
 * Uses SHA256 on the given string and compares it with the first SHA256_DIGEST_LENGTH-bytes
 * which should be the stored master password.
 * @param pwList pwList struct
 * @param master_pw the entered password in plain text
 * @return true if hashes match, false otherwise
 */
bool check_master_pw(const pw_list_t *pwList, const char *master_pw) {
    rewind(pwList->file);
    /* read in and compare */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    fread(hash, 1, sizeof(hash), pwList->file);

    // Compute the hash of the new string
    unsigned char new_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)master_pw, strlen(master_pw), new_hash);

    // Compare the two hashes
    if (memcmp(hash, new_hash, SHA256_DIGEST_LENGTH) == 0) {
        return true;
    }else{
        return false;
    }
}


/** Save the new password hash in binary to the file.
 * The given string gets hashed with SHA256 and written at the beginning of the file, where
 * the master pw should be stored.
 * @param pwList a pointer to pwList struct
 * @param new_pw the new password in plain text
 */
void save_master_pw(pw_list_t *pwList, char *new_pw) {
    strcpy(pwList->master_pw, new_pw);
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256((const unsigned char*)pwList->master_pw, strlen(pwList->master_pw), hash);

    rewind(pwList->file);
    fwrite(hash, 1, sizeof(hash), pwList->file);
}


/** Encrypts the pwList entries and saves it to a file.
 * Saves the master password hash and the AES256-encrypted content to file.
 * @param pwList pointer to pw_list_t struct
 * @return error code
 */
int save_to_file(pw_list_t *pwList){
    FILE* temp = fopen("temp.txt", "w");

    /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
   status of enc/dec operations */
    EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();
    
    /* Generate salt */
    unsigned char salt[SALT_BYTES];
    randombytes_buf(&salt, sizeof(salt));

    /* Get the password data */
    unsigned char *key_data = (unsigned char *)pwList->master_pw;
    int key_data_len = strlen(key_data);

    /* gen key and iv. init the cipher ctx object */
    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, en, de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }

    /* Save master pw and salt*/
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pwList->master_pw, strlen(pwList->master_pw), hash);
    rewind(temp);
    fwrite(hash, 1, sizeof(hash), temp);
    fwrite(salt, 1, sizeof(salt), temp);

    /* Encrypt entries and save them */
    unsigned char *ciphertext;
    int len = strlen(pwList->entries);
    ciphertext = aes_encrypt(en, (unsigned char *)pwList->entries, &len);
    fwrite(ciphertext, 1, len, temp);

    free(ciphertext);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    fclose(temp);

    /* replacing the old file */
    fclose(pwList->file);
    remove(pwList->filename);
    rename("temp.txt", pwList->filename);
    pwList->file = fopen(pwList->filename, "r+");
}


/** Load a pw file.
 * Load and decrypt the content of a pw file and save it in the pwList->content variable.
 * @param pwList pw list struct
 * @return error code
 */
int load_pw_file_content(pw_list_t *pwList){
    /* get file size */
    fseek(pwList->file, 0, SEEK_END);
    unsigned long file_size = ftell(pwList->file);
    unsigned int header_length = SHA256_DIGEST_LENGTH + SALT_BYTES;
    unsigned long content_size = file_size - header_length;

    /* store the encrypted values from the file in an array */
    fseek(pwList->file, SHA256_DIGEST_LENGTH, SEEK_SET);
    unsigned char salt[SALT_BYTES];
    fread(salt, 1, sizeof(salt), pwList->file);

    unsigned char enc_file_text[content_size];
    int bytes_read = fread(enc_file_text, 1, content_size, pwList->file);
    if (bytes_read != content_size) {
        printf("Error reading file\n");
        return 1;
    }

    /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
        status of enc/dec operations */
    EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();

    unsigned char *key_data;
    int key_data_len;

    key_data = (unsigned char *)pwList->master_pw;
    key_data_len = strlen(key_data);

    /* gen key and iv. init the cipher ctx object */
    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, en, de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }

    int len = content_size;
    unsigned char *plaintext;
    plaintext = (unsigned char*) aes_decrypt(de, enc_file_text, &len);
    unsigned char* entries = (unsigned char*) (plaintext + 1); // remove leading newline

    unsigned int raw_len = strlen(entries) + 1;
    unsigned int blocks = (raw_len / ENTRIES_BLOCK_SIZE) + 1;
    size_t memory_size = blocks * ENTRIES_BLOCK_SIZE;

    /* Allocate memory and save the content */
    free(pwList->entries); // Free the previously allocated memory
    pwList->entries = calloc(blocks * ENTRIES_BLOCK_SIZE, sizeof(unsigned char));
    if (pwList->entries == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    pwList->size = blocks;
    strncpy(pwList->entries, entries, len);
    pwList->entries[len] = '\0';

    pwList->entry_count = get_entry_count(pwList);

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    free(plaintext);

    return 0;
}