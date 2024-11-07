#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void self_delete(const char *file_path) {
    // Overwrite memory
    FILE *file = fopen(file_path, "r+");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *mem = (unsigned char *)malloc(size);
    if (mem == NULL) {
        perror("Failed to allocate memory");
        fclose(file);
        return;
    }

    srand(time(NULL));
    for (size_t i = 0; i < size; i++) {
        mem[i] = rand() % 256;
    }

    fwrite(mem, 1, size, file);
    fclose(file);
    free(mem);
    // Delete file
    unlink(file_path);
}