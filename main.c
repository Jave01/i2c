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


/* custom imports */
#include "files.h"
#include "main.h"


/**********************************************************************************************
 * Private function Headers
 **********************************************************************************************/
static void get_db_name(unsigned char* name);
static void request_new_password(unsigned char* output);


/**********************************************************************************************
 * Main function
 **********************************************************************************************/
int main()
{
    pw_list_t pwList = {
            .file = NULL,
            .filename = malloc(sizeof(char) * MAX_DB_NAME_LEN),
            .master_pw = malloc(sizeof(char) * MAX_MASTER_PW_LEN)
            };

    /* startup sequence */
    char inp;
    while(pwList.file == NULL){
        printf("Enter o for opening a database, c for creating one or q to quit:\n> ");
        scanf(" %c", &inp);

        fgetc(stdin); // remove whitespace for further scanning.

        if(inp == 'o'){
            get_db_name(pwList.filename);

            pwList.file = fopen(pwList.filename, "r+");
            if(pwList.file != NULL){
                char buf[SHA256_STR_LEN + 1] = {0};
                fgets(buf, SHA256_STR_LEN + 1, pwList.file);
                if(strlen(buf) != SHA256_STR_LEN){
                    printf("File is not of correct format or corrupted\n");
                    fclose(pwList.file);
                    pwList.file = NULL;
                } else {
                    printf("Database loaded successfully\n");
                }
            }else {
                printf("\n");
                perror("Error opening file");
                continue;
            }
        } else if(inp == 'c'){
            get_db_name(pwList.filename);

            /* check if file already exists */
            pwList.file = fopen(pwList.filename, "r");
            if(pwList.file != NULL){
                printf("File already exists\n");
                fclose(pwList.file);
                pwList.file = NULL;
                pwList.filename = NULL;
                continue;
            }

            /* create new file */
            pwList.file = fopen(pwList.filename, "w");
            pwList.entry_count = 0;
            if(pwList.file == NULL){
                perror("Error creating file");
                continue;
            }
            /* reopen file in update mode */
            fclose(pwList.file);
            pwList.file = fopen(pwList.filename, "r+");

            request_new_password(pwList.master_pw);
            save_master_pw(&pwList, pwList.master_pw);

            printf("Database created successfully\n");

        }else if(inp == 'q'){
            printf("quitting\n");
            return 0;
        }
        else{
            printf("not a valid option\n");
            continue;
        }
    }

    /* main sequence */
    bool running = true;
    printf("Enter a command. Valid commands can be displayed with 'h'\n");
    while(running){
        printf("> ");
        scanf(" %c", &inp);
        switch (inp) {
            case 'a': {
                char key[MAX_KEY_LEN], val[MAX_VAL_LEN];
                char* scanf_arg[10];

                sprintf(scanf_arg, "%%%ds", MAX_KEY_LEN-1); // construct format string with the
                printf("Enter the key:");
                scanf(scanf_arg, key);

                sprintf(scanf_arg, "%%%ds", MAX_VAL_LEN-1);
                printf("Enter the value:");
                scanf(scanf_arg, val);

                printf("Your key:value pair: %s:%s\n", key, val);

                set_entry(&pwList, key, val);

                break;
            }
            case 'e':
                printf("editing not implemented yet\n");
                break;
            case 'q':
                printf("quitting...\n");
                running = false;
                break;
            case 'r':
                printf("remove not implemented yet\n");
                break;
            case 'h':
                printf("Summary of valid character inputs:\nh - Help\na - add entry\ne - edit entry\nr - remove entry\nq - quit application\n");
                break;
            default:
                printf("Invalid option\n");
        }
    }

    fclose(pwList.file);
    pwList.file = NULL;
/* ------ hashing -------- */
//    pw_list_t pwList = {
//            .filename = "pw.txt",
//            .file = fopen("pw.txt", "r+"),
//    };
//
//    save_master_pw(&pwList, "super-secret-master-pw");
//
//    bool result = check_master_pw(&pwList, "super-secret-master-pw");
//    if (result){
//        printf("Hashes do match\n");
//    } else{
//        printf("Hashes do not match\n");
//    }
//
//    fclose(pwList.file);
//    pwList.file = NULL;
//    return 0;
}


/**********************************************************************************************
 * private functions
 **********************************************************************************************/
static void get_db_name(unsigned char* name){
    char* scanf_arg[10];

    printf("Enter a DB name (max length %d): ", MAX_DB_NAME_LEN-1);

    sprintf(scanf_arg, "%%%ds", MAX_DB_NAME_LEN-1); // construct format string with the
    scanf(scanf_arg, name);
}

static void request_new_password(unsigned char* output){
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

