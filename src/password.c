/*
 * Filename: password.c
 * Author: David Jäggli
 * Date: 28.3.2023
 * Description: Utility messing with passwords specifically copying to clipboard and generating passwords.
 *
 */

/**********************************************************************************************
 * Includes
 **********************************************************************************************/
/* external libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* custom imports */
#include "password.h"
#include "files.h"


/**********************************************************************************************
 * Private function headers
 **********************************************************************************************/
static int isXclipInstalled();


/**********************************************************************************************
 * Function definitions
 **********************************************************************************************/
/**
 * WIP
 * @param dest
 */
void generate_passwd(unsigned char *dest, const passwordGenComplexity complexity, int pw_len)
{
    if(pw_len < 1 || pw_len > MAX_VAL_LEN){
        printf("Password length not valid\n");
        return;
    }

    char charset[MAX_PASSWORD_CHARSET_LEN+1] = {0};

    switch (complexity) {
        case WEAK:
            strcpy(charset, PASSWORD_COMPLEXITY_LOW_CHARSET);
            break;
        case MEDIUM:
            strcpy(charset, PASSWORD_COMPLEXITY_MEDIUM_CHARSET);
            break;
        case STRONG:
            strcpy(charset, PASSWORD_COMPLEXITY_HIGH_CHARSET);
            break;
        default:
            printf("invalid password generation complexity\n");
            break;
    }

    unsigned char random_bytes[pw_len];
    randombytes_buf(random_bytes, pw_len);

    int char_index;
    for (int i = 0; i < pw_len; ++i) {
        char_index = random_bytes[i] % strlen(charset);
        dest[i] = charset[char_index];
    }
    dest[pw_len] = '\0';
    printf("generated password: %s\n", dest);
}


/**
 * Copies string to clipboard.
 * Uses the xclip command line tool on linux and the windows API on windows.
 * @param str string to copy to clipboard
 */
void copy_to_clipboard(const char *str){
#ifdef _WIN32
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(str) + 1);
    if (hMem == NULL) return;
    
    strcpy_s((char*)GlobalLock(hMem), strlen(str) + 1, str);
    GlobalUnlock(hMem);
    
    OpenClipboard(NULL);
    EmptyClipboard();
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
#endif
#ifdef __linux__
    // Check if xclip is installed
    if (!isXclipInstalled()) {
        printf("\033[1;33m");  // set color to yellow
        printf("Warning: xclip package is not installed. Please install xclip to enable clipboard functionality.\n");
        printf("\033[0m");  // reset color
        return;
    }

    char command[256];
    snprintf(command, sizeof(command), "echo '%s' | xclip -selection clipboard", str);
    system(command);
#endif

printf("Copied '%s' to clipboard\n", str);
}


static int isXclipInstalled() {
    FILE* pipe = popen("which xclip", "r");
    if (pipe != NULL) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            // Check if the output contains a valid path
            if (strlen(buffer) > 1) {
                pclose(pipe);
                return 1;  // xclip is installed
            }
        }
        pclose(pipe);
    }
    return 0;  // xclip is not installed
}