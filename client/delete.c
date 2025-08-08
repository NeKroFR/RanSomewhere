#include "delete.h"
#include "aes.h"
#include "common.h"

// Overwrites the binary with random data and deletes it.
int self_delete(const char *file_path) {
    int err = ERR_SUCCESS;
    if (!file_path) {
        err = ERR_INVALID_ARG;
        return err;
    }
    FILE *file = fopen(file_path, "rb+");
    if (!file) {
        err = ERR_FILE_OPEN;
        return err;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        err = ERR_GENERAL;
        fclose(file);
        return err;
    }
    long size = ftell(file);
    if (size == -1L) {
        err = ERR_GENERAL;
        fclose(file);
        return err;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        err = ERR_GENERAL;
        fclose(file);
        return err;
    }
    unsigned char *mem = malloc((size_t)size);
    if (!mem) {
        err = ERR_MEMORY_ALLOC;
        fclose(file);
        return err;
    }
    if (generate_random_key(mem, (size_t)size) != ERR_SUCCESS) {
        err = ERR_CRYPTO_OP;
        free(mem);
        fclose(file);
        return err;
    }
    size_t written = fwrite(mem, 1, (size_t)size, file);
    free(mem);
    if (written != (size_t)size) {
        err = ERR_GENERAL;
        fclose(file);
        return err;
    }
    if (fclose(file) != 0) {
        err = ERR_GENERAL;
        return err;
    }
    if (!DeleteFileA(file_path)) {
        err = ERR_GENERAL;
    }
    return err;
}
