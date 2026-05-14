#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <core/types.h>
#include <sodium.h>
#include <ctype.h>

void printhex(u8* bytes, size_t n)
{
	for (int i = 0; i < n; i++) {
		printf("%02x ", bytes[i]);
	}

	printf("\n");
}

void strnhash(u8* hash, size_t n, const char* str)
{
	if (str == NULL)
		return;

	size_t inlen = strlen(str);
	if (inlen == 0)
		return;

	u8 full_hash[crypto_generichash_BYTES];
	crypto_generichash(full_hash, sizeof(full_hash), (u8*)str, inlen, NULL, 0);
	memcpy(hash, full_hash, n);
}

void trim_ends(char* str)
{
	if (str == NULL || *str == '\0')
		return;

	size_t len = strlen(str);
	size_t start = 0;
	size_t end = len - 1;

	while (start < len && isspace(str[start]))
		start++;

	while (end >= start && isspace(str[end]))
		end--;

	int new_len = end - start + 1;
	if (start > 0) {
		memmove(str, str + start, new_len);
	}

	str[new_len] = '\0';
}

int read_to_string(char* str, size_t length, FILE* file)
{
	if (length < 2) {
		return -1;
	}

	size_t read_total = 0;
	while (read_total < length) {
		size_t read = fread(str + read_total, 1, length - read_total, file);
		if (read == 0) {
			if (feof(file))
				break;
			if (ferror(file)) {
				perror("fread");
				return -1;
			}
		}

		read_total += read;
	}

	str[length - 1] = '\0';
	return 0;
}

size_t strnlen(const char* s, size_t maxlen)
{
	size_t i;
	for (i = 0; i < maxlen && s[i]; ++i)
		;
	return i;
}

char* strndup(const char* s, size_t n)
{
	size_t len = strnlen(s, n);
	char* out = (char*)malloc(len + 1);
	if (out == NULL)
		return NULL;

	memcpy(out, s, len);
	out[len] = '\0';
	return out;
}
