#ifndef STRING_H
#define STRING_H

#include <string.h>

char* read_to_string(const char* path, size_t* outlen);
size_t strnlen(const char* s, size_t maxlen);
char* strndup(const char* s, size_t n);

#endif
