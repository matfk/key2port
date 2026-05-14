#ifndef STRING_H
#define STRING_H

#include <string.h>
#include <stdio.h>
#include <core/types.h>

void strnhash(u8* hash, size_t n, const char* str);
void trim_ends(char* str);
char* read_to_string(char* str, size_t length, FILE* file);
size_t strnlen(const char* s, size_t maxlen);
char* strndup(const char* s, size_t n);

#endif
