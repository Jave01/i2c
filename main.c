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


/* custom imports */
#include "files.h"
#include "crypto.h"


/**********************************************************************************************
 * Private function Headers
 **********************************************************************************************/
void get_db_name(char* name);


/**********************************************************************************************
 * Main function
 **********************************************************************************************/
int main()
{
    FILE* fp = NULL;

    char inp;
    while (fp == NULL){
        printf("Enter o for opening a database or c for creating one:\n> ");
        scanf(" %c", &inp);
        printf("%c\n", inp);
        fgetc(stdin);
        char name[MAX_DB_NAME_LEN];
        if(inp == 'o'){
            get_db_name(name);

            fp = fopen(name, "r");
            if(fp != NULL){
                printf("Database loaded successfully\n");
                break;
            }else {
                perror("Error opening file");
                continue;
            }
        } else if(inp == 'c'){
            get_db_name(name);

            /* check if file already exists */
            fp = fopen(name, "r");
            if(fp != NULL){
                printf("File already exists\n");
                fclose(fp);
                fp = NULL;
                continue;
            }

            /* create new file */
            fp = fopen(name, "w");
            if(fp == NULL){
                perror("Error creating file");
                continue;
            }

            printf("Database created successfully\n");
        }else{
            printf("not a valid option");
            return -1;
        }
    }

/* ------ hashing -------- */
//    pw_list_t pwList = {
//            .filename = "pw.txt",
//            .file = fopen("pw.txt", "r+"),
//    };
//
//    set_master_pw(&pwList, "super-secret-master-pw");
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
void get_db_name(char* name){
    printf("Enter a DB name (max length %d): ", MAX_DB_NAME_LEN-1);
    fgets(name, MAX_DB_NAME_LEN-1, stdin); // read up to MAX_LEN-1 characters from standard input
    if (name[strlen(name) - 1] != '\n') {
        int ch; // if the name was longer than MAX_LEN-1, discard any extra characters
        while ((ch = getchar()) != '\n' && ch != EOF);
    }
    name[strcspn(name, "\n")] = '\0'; // remove the newline character at the end of the name
}


