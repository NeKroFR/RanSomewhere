#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int hex_to_bytes(const char *hex, unsigned char *bytes, int blen) {
    for (int i = 0; i < blen; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &bytes[i]) != 1) {
            return 0;
        }
    }
    return 1;
}

unsigned long bytes_to_long(const unsigned char *bytes, int blen) {
    unsigned long value = 0;
    for (int i = 0; i < blen; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

int long_to_bytes(unsigned long value, unsigned char *bytes, int blen) {
    for (int i = blen - 1; i >= 0; i--) {
        bytes[i] = value & 0xff;
        value >>= 8;
    }
    return 1;
}

