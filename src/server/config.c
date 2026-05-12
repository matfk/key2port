#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <server/config.h>

int config_load(const char* path, config_t* config)
{
	FILE* fp = fopen(path, "r");
	if (fp == NULL) {
		return 1;
	}

	memset(config, 0, sizeof(config_t));
	return 0;
}
