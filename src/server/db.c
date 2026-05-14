#include <stdio.h>
#include <string.h>
#include <server/db.h>
#include <server/config.h>
#include <libspa/key.h>
#include <dirent.h>
#include <sqlite3.h>

static sqlite3* db = NULL;

int db_load_keys(const char* directory_path)
{
	DIR* dir = opendir(directory_path);
	if (dir == NULL) {
		perror("opendir");
		return -1;
	}

	struct dirent* entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_type == DT_DIR) {
			continue;
		}

		char full_path[PATH_MAX];
		snprintf(full_path, PATH_MAX, "%s/%s", directory_path, entry->d_name);
		printf("file: %s\n", full_path);
	}

	closedir(dir);
	return 0;
}

int db_init()
{
	if (db) {
		return 0;
	}

	const config_t* config = config_get();

	if (sqlite3_open(config->sqlite_db, &db) != SQLITE_OK) {
		fprintf(stderr, "failed to open database: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	char* err = NULL;
	const char* sql_seen = "CREATE TABLE IF NOT EXISTS seen ("
			       "nonce TEXT PRIMARY KEY, "
			       "timestamp INTEGER);";

	if (sqlite3_exec(db, sql_seen, 0, 0, &err) != SQLITE_OK) {
		fprintf(stderr, "sql error: %s\n", err);
		sqlite3_free(err);
		return -1;
	}

	const char* sql_keys = "CREATE TABLE IF NOT EXISTS keys ("
			       "id INT PRIMARY KEY, "
			       "username TEXT, "
			       "key TEXT);";

	if (sqlite3_exec(db, sql_keys, 0, 0, &err) != SQLITE_OK) {
		fprintf(stderr, "sql error: %s\n", err);
		sqlite3_free(err);
		return -1;
	}

	if (db_load_keys(config->keys) != 0) {
		fprintf(stderr, "no keys loaded\n");
		sqlite3_free(err);
		return -1;
	}

	sqlite3_free(err);
	return 0;
}

void db_close()
{
	if (db) {
		sqlite3_close(db);
		db = NULL;
	}
}
