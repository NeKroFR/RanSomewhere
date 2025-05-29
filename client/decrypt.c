#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define AES_KEY_SIZE 32
#define IV_SIZE 16
#define MAX_PATH 260

void reverse_bytes(unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        unsigned char temp = bytes[i];
        bytes[i] = bytes[len - 1 - i];
        bytes[len - 1 - i] = temp;
    }
}

int rsa_decrypt(const unsigned char *encrypted, size_t encrypted_len, BCRYPT_KEY_HANDLE hKey, 
                unsigned char *decrypted, size_t *decrypted_len) {
    BCRYPT_OAEP_PADDING_INFO paddingInfo = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)encrypted, (ULONG)encrypted_len, &paddingInfo,
                                    NULL, 0, decrypted, *decrypted_len, (ULONG*)decrypted_len, 
                                    BCRYPT_PAD_OAEP);
    return BCRYPT_SUCCESS(status);
}

BCRYPT_KEY_HANDLE import_rsa_private_key(const char *privkey_hex) {
    char *components[7];
    char *dup = strdup(privkey_hex);
    char *token = strtok(dup, "-");
    int i = 0;
    while (token && i < 7) {
        components[i++] = token;
        token = strtok(NULL, "-");
    }
    if (i < 2) {  // At least n and d are required
        free(dup);
        return NULL;
    }
    char *n_hex = components[0];
    char *d_hex = components[1];
    char *p_hex = (i > 2) ? components[2] : NULL;
    char *q_hex = (i > 3) ? components[3] : NULL;
    char *dp_hex = (i > 4) ? components[4] : NULL;
    char *dq_hex = (i > 5) ? components[5] : NULL;
    char *qinv_hex = (i > 6) ? components[6] : NULL;

    unsigned char n_bytes[256], d_bytes[256];
    unsigned char p_bytes[128] = {0}, q_bytes[128] = {0}, dp_bytes[128] = {0}, dq_bytes[128] = {0}, qinv_bytes[128] = {0};
    
    if (!hex_to_bytes(n_hex, n_bytes, 256) || !hex_to_bytes(d_hex, d_bytes, 256)) {
        free(dup);
        return NULL;
    }
    if (p_hex && !hex_to_bytes(p_hex, p_bytes, 128)) { free(dup); return NULL; }
    if (q_hex && !hex_to_bytes(q_hex, q_bytes, 128)) { free(dup); return NULL; }
    if (dp_hex && !hex_to_bytes(dp_hex, dp_bytes, 128)) { free(dup); return NULL; }
    if (dq_hex && !hex_to_bytes(dq_hex, dq_bytes, 128)) { free(dup); return NULL; }
    if (qinv_hex && !hex_to_bytes(qinv_hex, qinv_bytes, 128)) { free(dup); return NULL; }

    reverse_bytes(n_bytes, 256);
    reverse_bytes(d_bytes, 256);
    if (p_hex) reverse_bytes(p_bytes, 128);
    if (q_hex) reverse_bytes(q_bytes, 128);
    if (dp_hex) reverse_bytes(dp_bytes, 128);
    if (dq_hex) reverse_bytes(dq_bytes, 128);
    if (qinv_hex) reverse_bytes(qinv_bytes, 128);

    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        free(dup);
        return NULL;
    }

    size_t blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 256 + 128 + 128 + 128 + 128 + 128 + 256;
    BCRYPT_RSAKEY_BLOB *keyBlob = (BCRYPT_RSAKEY_BLOB *)malloc(blobSize);
    if (!keyBlob) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        free(dup);
        return NULL;
    }
    keyBlob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    keyBlob->BitLength = 2048;
    keyBlob->cbPublicExp = 3;
    keyBlob->cbModulus = 256;
    keyBlob->cbPrime1 = 128;
    keyBlob->cbPrime2 = 128;

    unsigned char exponent[] = {0x01, 0x00, 0x01}; // e = 65537 little-endian
    unsigned char *ptr = (unsigned char *)keyBlob + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(ptr, exponent, 3);
    ptr += 3;
    memcpy(ptr, n_bytes, 256);
    ptr += 256;
    memcpy(ptr, p_bytes, 128);
    ptr += 128;
    memcpy(ptr, q_bytes, 128);
    ptr += 128;
    memcpy(ptr, dp_bytes, 128);
    ptr += 128;
    memcpy(ptr, dq_bytes, 128);
    ptr += 128;
    memcpy(ptr, qinv_bytes, 128);
    ptr += 128;
    memcpy(ptr, d_bytes, 256);

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hKey, 
                                 (PUCHAR)keyBlob, (ULONG)blobSize, 0);
    free(keyBlob);
    free(dup);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hKey;
}

int decrypt_file_aes_cbc(const char *filepath, const unsigned char *aes_key) {
    HANDLE hInput = INVALID_HANDLE_VALUE, hOutput = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    unsigned char iv[16];
    BOOL success = FALSE;
    DWORD bytesRead, bytesWritten;
    unsigned char buffer[4096];
    ULONG decryptedLen;
    NTSTATUS status;
    char tempFile[MAX_PATH];

    hInput = CreateFile(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInput == INVALID_HANDLE_VALUE) return 0;

    success = ReadFile(hInput, iv, 16, &bytesRead, NULL);
    if (!success || bytesRead != 16) goto cleanup;

    snprintf(tempFile, sizeof(tempFile), "%s.dec", filepath);
    hOutput = CreateFile(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        CloseHandle(hInput);
        return 0;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, 
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)aes_key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    status = BCryptSetProperty(hKey, BCRYPT_INITIALIZATION_VECTOR, iv, 16, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    while (ReadFile(hInput, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (bytesRead < sizeof(buffer)) {
            status = BCryptDecrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                                   NULL, 0, &decryptedLen, BCRYPT_BLOCK_PADDING);
            if (!BCRYPT_SUCCESS(status)) goto cleanup;
        } else {
            status = BCryptDecrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                                   NULL, 0, &decryptedLen, 0);
            if (!BCRYPT_SUCCESS(status)) goto cleanup;
        }

        unsigned char *decrypted = malloc(decryptedLen);
        if (!decrypted) goto cleanup;

        if (bytesRead < sizeof(buffer)) {
            status = BCryptDecrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                                   decrypted, decryptedLen, &decryptedLen, BCRYPT_BLOCK_PADDING);
        } else {
            status = BCryptDecrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                                   decrypted, decryptedLen, &decryptedLen, 0);
        }
        if (!BCRYPT_SUCCESS(status)) {
            free(decrypted);
            goto cleanup;
        }

        success = WriteFile(hOutput, decrypted, decryptedLen, &bytesWritten, NULL);
        free(decrypted);
        if (!success || bytesWritten != decryptedLen) goto cleanup;
    }

    CloseHandle(hInput);
    CloseHandle(hOutput);
    hInput = hOutput = INVALID_HANDLE_VALUE;
    if (!MoveFileEx(tempFile, filepath, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFile(tempFile);
        return 0;
    }
    return 1;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hInput != INVALID_HANDLE_VALUE) CloseHandle(hInput);
    if (hOutput != INVALID_HANDLE_VALUE) {
        CloseHandle(hOutput);
        DeleteFile(tempFile);
    }
    return 0;
}
