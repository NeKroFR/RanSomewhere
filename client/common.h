#ifndef COMMON_H
#define COMMON_H

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 32
#define IV_SIZE 16
#define HMAC_SIZE 32 // SHA-256
#define RSA_MODULUS_SIZE 256
#define RSA_PRIME_SIZE 128
#define RSA_BIT_LENGTH 2048
#define RSA_EXPONENT_BYTES 3
#define BUFFER_CHUNK_SIZE 4096
#define MAX_CONFIG_LINE 1024
#define PRIVKEY_BUFFER_SIZE 8192 // Larger for safety
#define ERR_SUCCESS 0
#define ERR_INVALID_ARG -1
#define ERR_MEMORY_ALLOC -2
#define ERR_FILE_OPEN -3
#define ERR_CRYPTO_OP -4
#define ERR_NETWORK -5
#define ERR_GENERAL -6
#define ERR_INTEGRITY_FAIL -7 // New for HMAC

void zero_memory(void *mem, size_t len);

#endif // COMMON_H
