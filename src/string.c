#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* read_to_string(const char* path, size_t* outlen)
{
	FILE* file = fopen(path, "rb");
	if (file == NULL) {
		perror("fopen");
		return NULL;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		perror("fseek");
		return NULL;
	}

	long int file_size = ftell(file);
	if (file_size > 4096) {
		fprintf(stderr, "File too big\n");
		return NULL;
	}

	if (fseek(file, 0, SEEK_SET) != 0) {
		perror("fseek");
		return NULL;
	}

	char* pem = malloc(file_size + 1);
	if (pem == NULL) {
		perror("malloc");
		return NULL;
	}

	size_t read_total = 0;
	while (read_total < file_size) {
		size_t read = fread(pem + read_total, 1, file_size - read_total, file);
		if (read == 0) {
			if (feof(file))
				break;
			if (ferror(file)) {
				perror("fread");
				free(pem);
				fclose(file);
				return NULL;
			}
		}

		read_total += read;
	}

	fclose(file);
	pem[file_size] = '\0';
	if (outlen != NULL)
		*outlen = file_size;

	return pem;
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
