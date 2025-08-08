#include "decrypt.h"
#include "utils.h"
#include "common.h"
#include "aes.h"

int rsa_decrypt(const unsigned char *encrypted, size_t encrypted_len, BCRYPT_KEY_HANDLE h_key, unsigned char *decrypted, size_t *decrypted_len) {
    int err = ERR_SUCCESS;
    if (!encrypted || encrypted_len == 0 || !h_key || !decrypted || !decrypted_len) {
        err = ERR_INVALID_ARG;
        return err;
    }
    BCRYPT_OAEP_PADDING_INFO padding_info = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    NTSTATUS status = BCryptDecrypt(h_key, (PUCHAR)encrypted, (ULONG)encrypted_len, &padding_info,
                                    NULL, 0, decrypted, (ULONG)*decrypted_len, (ULONG*)decrypted_len,
                                    BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status))
        err = ERR_CRYPTO_OP;
    return err;
}

BCRYPT_KEY_HANDLE import_rsa_private_key(const char *privkey_hex) {
    if (!privkey_hex)
        return NULL;
    char *dup = _strdup(privkey_hex);
    if (!dup)
        return NULL;
    char *components[7] = {0};
    char *token = strtok(dup, "-");
    size_t num_components = 0;
    while (token && num_components < 7) {
        components[num_components++] = token;
        token = strtok(NULL, "-");
    }
    if (num_components < 2) {
        free(dup);
        return NULL;
    }
    char *n_hex = components[0];
    char *d_hex = components[1];
    char *p_hex = (num_components > 2) ? components[2] : NULL;
    char *q_hex = (num_components > 3) ? components[3] : NULL;
    char *dp_hex = (num_components > 4) ? components[4] : NULL;
    char *dq_hex = (num_components > 5) ? components[5] : NULL;
    char *qinv_hex = (num_components > 6) ? components[6] : NULL;
    unsigned char n_bytes[RSA_MODULUS_SIZE] = {0};
    unsigned char d_bytes[RSA_MODULUS_SIZE] = {0};
    unsigned char p_bytes[RSA_PRIME_SIZE] = {0};
    unsigned char q_bytes[RSA_PRIME_SIZE] = {0};
    unsigned char dp_bytes[RSA_PRIME_SIZE] = {0};
    unsigned char dq_bytes[RSA_PRIME_SIZE] = {0};
    unsigned char qinv_bytes[RSA_PRIME_SIZE] = {0};
    if (hex_to_bytes(n_hex, n_bytes, sizeof(n_bytes)) != ERR_SUCCESS || hex_to_bytes(d_hex, d_bytes, sizeof(d_bytes)) != ERR_SUCCESS) {
        free(dup);
        return NULL;
    }
    size_t cb_prime1 = p_hex ? RSA_PRIME_SIZE : 0;
    size_t cb_prime2 = q_hex ? RSA_PRIME_SIZE : 0;
    if (p_hex && hex_to_bytes(p_hex, p_bytes, cb_prime1) != ERR_SUCCESS) {
        free(dup);
        return NULL;
    }
    if (q_hex && hex_to_bytes(q_hex, q_bytes, cb_prime2) != ERR_SUCCESS) {
        free(dup);
        return NULL;
    }
    if (dp_hex && hex_to_bytes(dp_hex, dp_bytes, cb_prime1) != ERR_SUCCESS) {
        free(dup);
        return NULL;
    }
    if (dq_hex && hex_to_bytes(dq_hex, dq_bytes, cb_prime2) != ERR_SUCCESS) {
        free(dup);
        return NULL;
    }
    if (qinv_hex && hex_to_bytes(qinv_hex, qinv_bytes, cb_prime1) != ERR_SUCCESS) {
        free(dup);
        return NULL;
    }
    reverse_bytes(n_bytes, sizeof(n_bytes));
    reverse_bytes(d_bytes, sizeof(d_bytes));
    if (p_hex)
        reverse_bytes(p_bytes, cb_prime1);
    if (q_hex)
        reverse_bytes(q_bytes, cb_prime2);
    if (dp_hex)
        reverse_bytes(dp_bytes, cb_prime1);
    if (dq_hex)
        reverse_bytes(dq_bytes, cb_prime2);
    if (qinv_hex)
        reverse_bytes(qinv_bytes, cb_prime1);
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        free(dup);
        return NULL;
    }
    size_t blob_size = sizeof(BCRYPT_RSAKEY_BLOB) + RSA_EXPONENT_BYTES + RSA_MODULUS_SIZE +
                       cb_prime1 + cb_prime2 + cb_prime1 + cb_prime2 + cb_prime1 + RSA_MODULUS_SIZE;
    BCRYPT_RSAKEY_BLOB *key_blob = (BCRYPT_RSAKEY_BLOB *)malloc(blob_size);
    if (!key_blob) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        free(dup);
        return NULL;
    }
    key_blob->Magic = BCRYPT_RSAPRIVATE_MAGIC;
    key_blob->BitLength = RSA_BIT_LENGTH;
    key_blob->cbPublicExp = RSA_EXPONENT_BYTES;
    key_blob->cbModulus = RSA_MODULUS_SIZE;
    key_blob->cbPrime1 = cb_prime1;
    key_blob->cbPrime2 = cb_prime2;
    unsigned char exponent[RSA_EXPONENT_BYTES] = {0x01, 0x00, 0x01};
    unsigned char *ptr = (unsigned char *)key_blob + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(ptr, exponent, RSA_EXPONENT_BYTES);
    ptr += RSA_EXPONENT_BYTES;
    memcpy(ptr, n_bytes, RSA_MODULUS_SIZE);
    ptr += RSA_MODULUS_SIZE;
    if (cb_prime1)
        memcpy(ptr, p_bytes, cb_prime1);
    ptr += cb_prime1;
    if (cb_prime2)
        memcpy(ptr, q_bytes, cb_prime2);
    ptr += cb_prime2;
    if (cb_prime1)
        memcpy(ptr, dp_bytes, cb_prime1);
    ptr += cb_prime1;
    if (cb_prime2)
        memcpy(ptr, dq_bytes, cb_prime2);
    ptr += cb_prime2;
    if (cb_prime1)
        memcpy(ptr, qinv_bytes, cb_prime1);
    ptr += cb_prime1;

    memcpy(ptr, d_bytes, RSA_MODULUS_SIZE);
    status = BCryptImportKeyPair(h_alg, NULL, BCRYPT_RSAPRIVATE_BLOB, &h_key, (PUCHAR)key_blob, (ULONG)blob_size, 0);
    free(key_blob);
    free(dup);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
        return NULL;
    }
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return h_key;
}

// Decrypts a file using AES-CBC, verifying HMAC integrity first.
// Process: Read IV, compute HMAC over ciphertext, verify, then decrypt chunks.
int decrypt_file_aes_cbc(const char *filepath, const unsigned char *key) {
    int err = ERR_SUCCESS;
    if (!filepath || !key) {
        err = ERR_INVALID_ARG;
        return err;
    }
    HANDLE h_input = INVALID_HANDLE_VALUE;
    HANDLE h_output = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    BCRYPT_ALG_HANDLE h_hmac_alg = NULL;
    BCRYPT_HASH_HANDLE h_hmac = NULL;
    unsigned char iv[IV_SIZE];
    unsigned char file_hmac[HMAC_SIZE];
    BOOL success = FALSE;
    DWORD bytes_read = 0, bytes_written = 0;
    unsigned char buffer[BUFFER_CHUNK_SIZE];
    ULONG decrypted_len = 0;
    NTSTATUS status;
    char temp_file[MAX_PATH] = {0};
    unsigned char hmac_key[HMAC_SIZE];
    if (_snprintf_s(temp_file, sizeof(temp_file), _TRUNCATE, "%s.dec", filepath) == -1) {
        err = ERR_GENERAL;
        return err;
    }
    if (derive_hmac_key(key, hmac_key) != ERR_SUCCESS) {
        err = ERR_CRYPTO_OP;
        return err;
    }
    h_input = CreateFileA(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_input == INVALID_HANDLE_VALUE) {
        err = ERR_FILE_OPEN;
        goto cleanup;
    }
    success = ReadFile(h_input, iv, sizeof(iv), &bytes_read, NULL);
    if (!success || bytes_read != sizeof(iv)) {
        err = ERR_GENERAL;
        goto cleanup;
    }
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(h_input, &file_size)) {
        err = ERR_GENERAL;
        goto cleanup;
    }
    size_t total_len = (size_t)file_size.QuadPart;
    if (total_len < sizeof(iv) + HMAC_SIZE) {
        err = ERR_GENERAL;
        goto cleanup;
    }
    size_t cipher_len = total_len - sizeof(iv) - HMAC_SIZE;
    status = BCryptOpenAlgorithmProvider(&h_hmac_alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    status = BCryptCreateHash(h_hmac_alg, &h_hmac, NULL, 0, hmac_key, HMAC_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    size_t remaining = cipher_len;
    while (remaining > 0) {
        DWORD to_read = (DWORD) min(sizeof(buffer), remaining);
        success = ReadFile(h_input, buffer, to_read, &bytes_read, NULL);
        if (!success || bytes_read != to_read) {
            err = ERR_GENERAL;
            goto cleanup;
        }
        status = BCryptHashData(h_hmac, buffer, bytes_read, 0);
        if (!BCRYPT_SUCCESS(status)) {
            err = ERR_CRYPTO_OP;
            goto cleanup;
        }
        remaining -= bytes_read;
    }
    success = ReadFile(h_input, file_hmac, sizeof(file_hmac), &bytes_read, NULL);
    if (!success || bytes_read != sizeof(file_hmac)) {
        err = ERR_GENERAL;
        goto cleanup;
    }
    unsigned char computed_hmac[HMAC_SIZE];
    status = BCryptFinishHash(h_hmac, computed_hmac, sizeof(computed_hmac), 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    if (constant_time_compare(computed_hmac, file_hmac, HMAC_SIZE) != 0) {
        err = ERR_INTEGRITY_FAIL;
        zero_memory(hmac_key, sizeof(hmac_key));
        goto cleanup;
    }
    SetFilePointer(h_input, sizeof(iv), NULL, FILE_BEGIN);
    h_output = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_output == INVALID_HANDLE_VALUE) {
        err = ERR_FILE_OPEN;
        goto cleanup;
    }
    status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    status = BCryptSetProperty(h_alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    status = BCryptGenerateSymmetricKey(h_alg, &h_key, NULL, 0, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    status = BCryptSetProperty(h_key, BCRYPT_INITIALIZATION_VECTOR, iv, sizeof(iv), 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    while (ReadFile(h_input, buffer, sizeof(buffer), &bytes_read, NULL)) {
        if (bytes_read == 0) {
            break;
        }
        ULONG flags = (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0;
        status = BCryptDecrypt(h_key, buffer, bytes_read, NULL, NULL, 0, NULL, 0, &decrypted_len, flags);
        if (!BCRYPT_SUCCESS(status)) {
            err = ERR_CRYPTO_OP;
            goto cleanup;
        }
        unsigned char *decrypted = malloc(decrypted_len);
        if (!decrypted) {
            err = ERR_MEMORY_ALLOC;
            goto cleanup;
        }
        status = BCryptDecrypt(h_key, buffer, bytes_read, NULL, NULL, 0, decrypted, decrypted_len, &decrypted_len, flags);
        if (!BCRYPT_SUCCESS(status)) {
            err = ERR_CRYPTO_OP;
            free(decrypted);
            goto cleanup;
        }
        success = WriteFile(h_output, decrypted, decrypted_len, &bytes_written, NULL);
        free(decrypted);
        if (!success || bytes_written != decrypted_len) {
            err = ERR_GENERAL;
            goto cleanup;
        }
    }
    if (h_input != INVALID_HANDLE_VALUE) {
        CloseHandle(h_input);
        h_input = INVALID_HANDLE_VALUE;
    }
    if (h_output != INVALID_HANDLE_VALUE) {
        CloseHandle(h_output);
        h_output = INVALID_HANDLE_VALUE;
    }
    if (!MoveFileExA(temp_file, filepath, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileA(temp_file);
        err = ERR_GENERAL;
        goto cleanup;
    }
    zero_memory(hmac_key, sizeof(hmac_key));
    return err;
cleanup:
    zero_memory(hmac_key, sizeof(hmac_key));
    if (h_hmac) {
        BCryptDestroyHash(h_hmac);
    }
    if (h_hmac_alg) {
        BCryptCloseAlgorithmProvider(h_hmac_alg, 0);
    }
    if (h_key) {
        BCryptDestroyKey(h_key);
    }
    if (h_alg) {
        BCryptCloseAlgorithmProvider(h_alg, 0);
    }
    if (h_input != INVALID_HANDLE_VALUE) {
        CloseHandle(h_input);
    }
    if (h_output != INVALID_HANDLE_VALUE) {
        CloseHandle(h_output);
        DeleteFileA(temp_file);
    }
    return err;
}
