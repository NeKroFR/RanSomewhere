#ifndef DECRYPT_H
#define DECRYPT_H

#include <windows.h>
#include <bcrypt.h>

#define AES_KEY_SIZE 32

BCRYPT_KEY_HANDLE import_rsa_private_key(const char *privkey_hex);
int rsa_decrypt(const unsigned char *encrypted, size_t encrypted_len, BCRYPT_KEY_HANDLE hKey, unsigned char *decrypted, size_t *decrypted_len);
int decrypt_file_aes_cbc(const char *filepath, const unsigned char *key);

#endif // DECRYPT_H
