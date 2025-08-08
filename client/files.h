#ifndef FILES_H
#define FILES_H

int create_readme(const char *content);
void append_to_paths(const char *filepath);
unsigned char *read_binary_file(const char *filepath, size_t *out_len);

#endif // FILES_H
