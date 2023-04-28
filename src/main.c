/*
 * Filename: main.c
 * Author: David Jäggli
 * Date: 14.3.2023
 * Description: Standard functions for reading, editing and data collection of
 *              password manager files.
 */


/**********************************************************************************************
 * Includes
 **********************************************************************************************/
/* external libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <sodium.h>


/* custom imports */
#include "files.h"
#include "main.h"
#include "password.h"

/**********************************************************************************************
 * Private function Headers
 **********************************************************************************************/
 /* user interaction */
static void get_db_name(unsigned char* name);
static void unlock_database(pw_list_t *pwList);
static void request_new_master_password(unsigned char* output);

/**********************************************************************************************
 * Global variables
 **********************************************************************************************/


/**********************************************************************************************
 * Main function
 **********************************************************************************************/
int main() {
    pw_list_t pwList = {
            .file = NULL,
            .filename = malloc(sizeof(char) * MAX_DB_NAME_LEN),
            .master_pw = malloc(sizeof(char) * MAX_MASTER_PW_LEN),
            .content = malloc(1024),
    };

    unsigned char text[] = "\nkey1:val1\nkey2:val2\nkey3:val3\n";

    strncpy(pwList.content, text, strlen(text));

    /* pw encryption test */
    pwList.filename = "pw.bbw";
    pwList.file = fopen(pwList.filename, "r+");

    if (pwList.file == NULL)
    {
        printf("Error opening file\n");
        return 1;
    }

    unsigned char salt[2];
    randombytes_buf(&salt, 2);
    printf("salt: %d %d\n", salt[0], salt[1]);



   save_master_pw(&pwList, "very_secret_key");
   int res = check_master_pw(&pwList, pwList.master_pw);
   printf("check master pw: %d\n", res);

   save_to_file(&pwList);
   load_pw_file(&pwList);
   printf("content:\n%s", pwList.content);
//
//
//    /* startup sequence */
//    char inp;
//    while (pwList.file == NULL) {
//        printf("Enter o for opening a database, c for creating one or q to quit:\n> ");
//        scanf(" %c", &inp);
//
//        fgetc(stdin); // remove whitespace for further scanning.
//
//        if (inp == 'o') {
//            get_db_name(pwList.filename);
//            unlock_database(&pwList);
//            if(pwList.file == NULL){
//                continue;
//            }
//        } else if (inp == 'c') {
//            get_db_name(pwList.filename);
//
//            /* check if file already exists */
//            pwList.file = fopen(pwList.filename, "r");
//            if (pwList.file != NULL) {
//                printf("File already exists\n");
//                fclose(pwList.file);
//                pwList.file = NULL;
//                pwList.filename = NULL;
//                continue;
//            }
//
//            /* create new file */
//            pwList.file = fopen(pwList.filename, "w");
//            pwList.entry_count = 0;
//            if (pwList.file == NULL) {
//                perror("Error creating file");
//                continue;
//            }
//            /* reopen file in update mode */
//            fclose(pwList.file);
//            pwList.file = fopen(pwList.filename, "r+");
//
//            request_new_master_password(pwList.master_pw);
//            save_master_pw(&pwList, pwList.master_pw);
//
//            printf("Database created successfully\n");
//
//        } else if (inp == 'q') {
//            printf("quitting\n");
//            return 0;
//        } else {
//            printf("not a valid option\n");
//            continue;
//        }
//    }
//
//    /* main sequence */
//    bool running = true;
//    printf("Enter a command. Valid commands can be displayed with 'h'\n");
//    while (running) {
//        printf("> ");
//        getchar(); // remove whitespace
//        inp = getchar();
//        switch (inp) {
//            case 'e': {
//                char key[MAX_KEY_LEN], val[MAX_VAL_LEN];
//                char *scanf_arg[10];
//
//                sprintf(scanf_arg, "%%%ds", MAX_KEY_LEN - 1); // construct format string
//                printf("Enter the key:");
//                scanf(scanf_arg, key);
//
//                sprintf(scanf_arg, "%%%ds", MAX_VAL_LEN - 1);
//                printf("Enter the value:");
//                scanf(scanf_arg, val);
//
//                set_entry(&pwList, key, val);
//
//                break;
//            }
//            case 'q':
//                printf("quitting...\n");
//                running = false;
//                break;
//            case 'r':
//                printf("remove not implemented yet\n");
//                break;
//            case 'h':
//                printf("Summary of valid character inputs:\ne - edit database\nr - remove entry\nq - quit application\nh - help\n");
//                break;
//            default:
//                printf("Invalid option\n");
//        }
//    }

    fclose(pwList.file);
    pwList.file = NULL;

    return 0;
}

/**********************************************************************************************
 * private functions
 **********************************************************************************************/
/**
 * Requests a new password from the user over cli.
 * @param name pointer to the variable where the name gets written to
 */
static void get_db_name(unsigned char* name){
    char scanf_arg[124];

    printf("Enter a DB name (max length %d): ", MAX_DB_NAME_LEN-1);

    fgets(name, MAX_DB_NAME_LEN, stdin);
}


/** WIP! currently only checks if entered password is correct, because encryption is not implemented yet
 *
 * @param pwList pointer to struct where file and password will be saved to.
 */
static void unlock_database(pw_list_t *pwList){
    bool pw_accepted = false;
    char pw[MAX_MASTER_PW_LEN + 1];
    char scanf_arg[5] = {0};

    pwList->file = fopen(pwList->filename, "r+");
    if (pwList->file != NULL) {
        char buf[SHA256_STR_LEN + 1] = {0};
        sprintf(scanf_arg, "%%%ds", MAX_MASTER_PW_LEN-1); // construct format string
        fgets(buf, SHA256_STR_LEN + 1, pwList->file);
        if (strlen(buf) != SHA256_STR_LEN) {
            printf("File is not of correct format or corrupted.\n");
            fclose(pwList->file);
            pwList->file = NULL;
            return;
        }
    } else {
        printf("\n");
        perror("Error opening file");
    }
    while(!pw_accepted){
        printf("Enter master password:");
        scanf(scanf_arg, pw);

        if(check_master_pw(pwList, pw)){
            pwList->master_pw = pw;
            pw_accepted=true;
            printf("Database loaded successfully\n");
        }else{
            printf("pw incorrect\n");
        }
    }
}


/**
 * Requests a new master password from the user.
 * @param output variable where the password gets written to.
 */
static void request_new_master_password(unsigned char* output){
    bool pw_accepted = false;
    char buf[MAX_MASTER_PW_LEN+1];
    char buf2[MAX_MASTER_PW_LEN+1];

    while(!pw_accepted){
        printf("Enter master password (extended ASCII only, no spaces, max %d chars):", MAX_MASTER_PW_LEN);
        scanf("%s", buf);
        printf("repeat:");
        scanf(" %s", buf2);
        if (strncmp(buf, buf2, MAX_MASTER_PW_LEN+1) != 0){
            printf("different passwords entered\n");
        }else{
            strncpy(output, buf, MAX_MASTER_PW_LEN+1);
            pw_accepted = true;
        }
    }
}


static void init_application(){
    srand(time(NULL));   // rng initialization
}