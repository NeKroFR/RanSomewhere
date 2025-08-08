#include "utils.h"
#include "common.h"

int hex_to_bytes(const char *hex, unsigned char *bytes, size_t blen) {
    if (!hex || !bytes || blen == 0)
        return ERR_INVALID_ARG;
    int err = ERR_SUCCESS;
    size_t hex_len = strlen(hex);
    if (hex_len != 2 * blen) {
        err = ERR_GENERAL;
        return err;
    }
    for (size_t i = 0; i < blen; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            err = ERR_GENERAL;
            return err;
        }
    }
    return err;
}

void reverse_bytes(unsigned char *bytes, size_t len) {
    if (!bytes || len == 0)
        return;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned char temp = bytes[i];
        bytes[i] = bytes[len - 1 - i];
        bytes[len - 1 - i] = temp;
    }
}

unsigned long bytes_to_long(const unsigned char *bytes, size_t blen) {
    unsigned long value = 0;
    for (size_t i = 0; i < blen; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

int long_to_bytes(unsigned long value, unsigned char *bytes, size_t blen) {
    int err = ERR_SUCCESS;
    if (!bytes || blen == 0) {
        err = ERR_INVALID_ARG;
        return err;
    }
    if (value >= (1UL << (8 * blen))) {
        err = ERR_GENERAL;
        return err;
    }
    for (int i = (int)blen - 1; i >= 0; i--) {
        bytes[i] = value & 0xff;
        value >>= 8;
    }
    return err;
}

int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len) {
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return (result == 0) ? 0 : -1;
}
