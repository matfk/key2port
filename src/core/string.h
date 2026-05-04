#ifndef STRING_H
#define STRING_H

#include <string.h>
#include <stdio.h>

char* read_to_string(char* str, size_t length, FILE* file);
size_t strnlen(const char* s, size_t maxlen);
char* strndup(const char* s, size_t n);

#endif
