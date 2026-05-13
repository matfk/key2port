#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <server/config.h>
#include <core/string.h>

static config_t config;

const config_t* config_get()
{
	return (const config_t*)&config;
}

int config_load(const char* path)
{
	FILE* fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen");
		return -1;
	}

	memset(&config, 0, sizeof(config_t));

	char line[PATH_MAX + 64];
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "interface = %31s", config.interface) == 1) {
			trim_ends(config.interface);
			continue;
		}

		if (sscanf(line, "sqlite_db = %4095s", config.sqlite_db) == 1) {
			trim_ends(config.sqlite_db);
			continue;
		}

		if (sscanf(line, "replay_window = %d", &config.replay_window) == 1) {
			continue;
		}

		if (sscanf(line, "ttl = %d", &config.ttl) == 1) {
			continue;
		}

		if (sscanf(line, "min_capture_port = %hd", &config.min_capture_port) == 1) {
			continue;
		}

		if (sscanf(line, "max_capture_port = %hd", &config.max_capture_port) == 1) {
			continue;
		}
	}

	fclose(fp);
	return 0;
}
