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
			return -1;
		}
	}

	if (error_path) {
		log_error = fopen(error_path, "a");
		if (log_error == NULL) {
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

	char buffer[4096];
	int n = vsnprintf(buffer, sizeof(buffer), fmt, args);
	if (n < 0) {
		return;
	}

	fwrite(buffer, 1, sizeof(buffer), log_file);
	fflush(log_file);
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
