#include "common.h"
void zero_memory(void *mem, size_t len) {
    if (mem)
        SecureZeroMemory(mem, len);
}
