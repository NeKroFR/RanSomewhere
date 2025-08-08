#ifndef AES_H
#define AES_H

int generate_random_key(unsigned char *key, size_t key_len);
int compute_hmac(const unsigned char *key, const unsigned char *data, size_t data_len, unsigned char *hmac);
int derive_hmac_key(const unsigned char *aes_key, unsigned char *hmac_key);
int encrypt_file_aes_cbc(const char *filepath, const unsigned char *key);
int encrypt_rsa_oaep(const unsigned char *data, size_t data_len, const char *rsa_n_hex, unsigned char **encrypted_key, size_t *encrypted_len);

#endif // AES_H
