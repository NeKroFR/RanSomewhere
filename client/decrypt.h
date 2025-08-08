#ifndef DECRYPT_H
#define DECRYPT_H

int rsa_decrypt(const unsigned char *encrypted, size_t encrypted_len, BCRYPT_KEY_HANDLE h_key, unsigned char *decrypted, size_t *decrypted_len);
BCRYPT_KEY_HANDLE import_rsa_private_key(const char *privkey_hex);
int decrypt_file_aes_cbc(const char *filepath, const unsigned char *key);

#endif // DECRYPT_H
