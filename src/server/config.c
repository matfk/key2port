#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <server/config.h>

void config_print(config_t* config)
{
	printf("interface = %s\n", config->interface);
	printf("sqlite_db = %s\n", config->sqlite_db);
	printf("replay_window = %d\n", config->replay_window);
	printf("ttl = %d\n", config->ttl);
	printf("min_capture_port = %d\n", config->min_capture_port);
	printf("max_capture_port = %d\n", config->max_capture_port);
}

int config_load(const char* path, config_t* config)
{
	FILE* fp = fopen(path, "r");
	if (fp == NULL) {
		return 1;
	}

	memset(config, 0, sizeof(config_t));

	char line[8192];
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (sscanf(line, "interface = %31s", config->interface) == 1) {
			continue;
		}

		if (sscanf(line, "sqlite_db = %4095s", config->sqlite_db) == 1) {
			continue;
		}

		if (sscanf(line, "replay_window = %d", &config->replay_window) == 1) {
			continue;
		}

		if (sscanf(line, "ttl = %d", &config->ttl) == 1) {
			continue;
		}

		if (sscanf(line, "min_capture_port = %hd", &config->min_capture_port) == 1) {
			continue;
		}

		if (sscanf(line, "max_capture_port = %hd", &config->max_capture_port) == 1) {
			continue;
		}
	}

	fclose(fp);
	return 0;
}
