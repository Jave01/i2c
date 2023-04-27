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
#include <stdio.h>
#include <openssl/sha.h>

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

    rewind(pwList->file);

    char buffer[MAX_LINE_LEN] = {0};
    while (fgets(buffer, MAX_LINE_LEN, pwList->file) != NULL) {
        lines++;
    }

    return lines;
}


/** Returns the value of the entry based on the key.
 * Writes the string into the str variable and returns the pointer to the value.
 * @param pwList  pointer to pw_file object
 * @param str destination where the value gets written into
 * @param key key to search for in the file
 * @return offset in the file, where the string is found
*/
long get_entry(pw_list_t *pwList, unsigned char *str, const unsigned char *key){
    int range = get_entry_count(pwList);

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
                    long pos = ftell(pwList->file);
                    if(fgets(str, MAX_VAL_LEN, pwList->file) != NULL){
                        return pos;
                    } else {
                        return 0;
                    }
                }
                else{
                    break;
                }
            }
        }
        while ((c = fgetc(pwList->file)) != '\n' && c != EOF);// go to next entry
    }
    rewind(pwList->file);
    return 0;
}


/** Change or create an entry in pw list.
 * If the entry key exists, the value gets overwritten, if it doesn't a new one is created.
 * @param pw_list a pointer to pw_list struct
 * @param key the key of the entry
 * @param val the value of the entry
 * @return bool if the action was successful
*/
bool set_entry(pw_list_t* pw_list, const unsigned char *key, const unsigned char *val){
    if (strlen(key) > MAX_KEY_LEN || strlen(key) < 1){
        printf("Key size invalid (%ld/%d chars)\n", strlen(key), MAX_KEY_LEN);
        return false;
    } else if (strlen(val) > MAX_VAL_LEN){
        printf("Value size invalid (%ld/%d chars)\n", strlen(val), MAX_VAL_LEN);
        return false;
    }

    /* some variables for determining the (maybe) existing entry */
    char entry_value[MAX_LINE_LEN];
    long entry_offset = get_entry(pw_list, entry_value, key);

    rewind(pw_list->file);

    /* create new entry_value if it doesn't exist */
    if (!entry_offset)
    {
        bool inp_valid = false;
        while(!inp_valid) {
            printf("Entry does not exist, create new one? [y/N]:");
            getchar(); // remove whitespace
            unsigned char inp = getchar();
            if (inp == 'n' || inp == 'N'){
                printf("Exiting edit mode\n");
                return false;
            } else if (!(inp == 'y')){
                printf("Input not valid\n");
            } else{
                inp_valid = true;
            }
        }
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
         * copy content */
        bool inp_valid = false;
        while(!inp_valid) {
            printf("Entry exists, do you want to update it's value? [y/n]:");
            getchar(); // remove whitespace
            char inp = getchar();
            if (inp == 'n'){
                printf("Exiting edit mode\n");
                return false;
            } else if (!(inp == 'y')){
                printf("Input not valid\n");
            } else{
                inp_valid = true;
            }
        }

        FILE* ftemp = fopen("temp.txt", "w");

        /* copy content up to the point where the entry is stored */
        rewind(pw_list->file);
        char c;
        for (int i = 0; i < entry_offset; ++i) {
            c = fgetc(pw_list->file);
            fputc(c, ftemp);
        }

        fputs(val, ftemp); // insert new value

        while((c = fgetc(pw_list->file)) != '\n'); // skip to the end of the old value

        fputc(c, ftemp); // insert the missing '\n' because it got skipped too in the line above

        while((c = fgetc(pw_list->file)) != EOF){
            fputc(c, ftemp);
        }

        /* replace old file */
        fclose(ftemp);
        fclose(pw_list->file);
        remove(pw_list->filename);
        rename("temp.txt", pw_list->filename);

        pw_list->file = fopen(pw_list->filename, "r+");
        if(pw_list->file == NULL){
            perror("Error while renaming temp file\n");
            return false;
        }

        printf("value updated successfully\n");
    }
    return true;
}


/** Check if entered string matches the master password saved in the file.
 * Uses SHA256 on the given string and compares it with the first SHA256_DIGEST_LENGTH-bytes
 * which should be the stored master password.
 * @param pwList pw_list struct
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
 * @param pwList a pointer to pw_list struct
 * @param new_pw the new password in plain text
 */
void save_master_pw(pw_list_t *pwList, char *new_pw) {
    strcpy(pwList->master_pw, new_pw);
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256((const unsigned char*)pwList->master_pw, strlen(pwList->master_pw), hash);

    rewind(pwList->file);
    fwrite(hash, 1, sizeof(hash), pwList->file);
}


/** Encrypts the pwList content and saves it to a file.
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

    unsigned int salt[] = {12345, 54321};
    unsigned char *key_data;
    int key_data_len;

    /* get the password data */
    key_data = (unsigned char *)pwList->master_pw;
    key_data_len = strlen(key_data);

    /* gen key and iv. init the cipher ctx object */
    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, en, de)) {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }

    /* Save master pw */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pwList->master_pw, strlen(pwList->master_pw), hash);
    rewind(temp);
    fwrite(hash, 1, sizeof(hash), temp);

    unsigned char *ciphertext;
    int len = strlen(pwList->content);
    ciphertext = aes_encrypt(en, (unsigned char *)pwList->content, &len);

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
int load_pw_file(pw_list_t *pwList){
    /* get file size */
    fseek(pwList->file, 0, SEEK_END);
    unsigned long file_size = ftell(pwList->file);
    unsigned int header_length = SHA256_DIGEST_LENGTH;
    unsigned long content_size = file_size - header_length;
    fseek(pwList->file, header_length, SEEK_SET);

    /* store the encrypted values from the file in an array */
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

    unsigned int salt[] = {12345, 54321};
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

    pwList->content = malloc(sizeof(unsigned char) * (len+1));
    strncpy(pwList->content, plaintext, len);
    pwList->content[len] = '\0';

    EVP_CIPHER_CTX_free(en);
    EVP_CIPHER_CTX_free(de);

    free(plaintext);

    return 0;
}