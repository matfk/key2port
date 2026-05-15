#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static FILE* log_auth = NULL;
static FILE* log_error = NULL;

int logs_open(const char* auth_path, const char* error_path)
{
	if (auth_path) {
		log_auth = fopen(auth_path, "a");
		if (log_auth == NULL) {
			perror("fopen");
			return -1;
		}
	}

	if (error_path) {
		log_error = fopen(error_path, "a");
		if (log_error == NULL) {
			perror("fopen");
			return -1;
		}
	}

	return 0;
}

void logs_close()
{
	if (log_auth) {
		fclose(log_auth);
	}

	if (log_error) {
		fclose(log_error);
	}
}

static void log_write(FILE* log_file, const char* fmt, va_list args)
{
	if (log_file == NULL || fmt == NULL) {
		return;
	}

	va_list aq;
	va_copy(aq, args);

	vfprintf(log_file, fmt, aq);
	fputc('\n', log_file);

	fflush(log_file);

	va_end(aq);
}

void log_auth_write(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	log_write(log_auth, fmt, ap);
	log_write(stdout, fmt, ap);

	va_end(ap);
}

void log_error_write(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	log_write(log_error, fmt, ap);
	log_write(stderr, fmt, ap);

	va_end(ap);
}
