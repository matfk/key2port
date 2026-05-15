#ifndef LOG_H
#define LOG_H

int logs_open(const char* auth_path, const char* error_path);
void logs_close();
void log_auth_write(const char* fmt, ...);
void log_error_write(const char* fmt, ...);

#define LOG_AUTH(...) log_auth_write(__VA_ARGS__)
#define LOG_ERROR(...) log_error_write(__VA_ARGS__)

#endif
