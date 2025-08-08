#ifndef UTILS_H
#define UTILS_H

int hex_to_bytes(const char *hex, unsigned char *bytes, size_t blen);
void reverse_bytes(unsigned char *bytes, size_t len);
unsigned long bytes_to_long(const unsigned char *bytes, size_t blen);
int long_to_bytes(unsigned long value, unsigned char *bytes, size_t blen);
int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len);

#endif // UTILS_H
