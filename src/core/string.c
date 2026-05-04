#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
