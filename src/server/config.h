#ifndef CONFIG_H
#define CONFIG_H

#include <core/types.h>
#include <stdlib.h>
#include <linux/limits.h>

typedef struct {
	char interface[32];
	char sqlite_db[PATH_MAX];
	u32 replay_window;
	u32 ttl;
	u16 min_capture_port;
	u16 max_capture_port;
} config_t;

void config_print(config_t* config);
int config_load(const char* path, config_t* config);

#endif
