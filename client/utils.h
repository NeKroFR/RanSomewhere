#ifndef UTILS_H
#define UTILS_H

int hex_to_bytes(const char *hex, unsigned char *bytes, int blen);

unsigned long bytes_to_long(const unsigned char *bytes, int blen);

int long_to_bytes(unsigned long value, unsigned char *bytes, int blen);


#endif // UTILS_H