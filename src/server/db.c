#include <stdio.h>
#include <string.h>
#include <server/db.h>
#include <server/config.h>
#include <core/string.h>
#include <libspa/key.h>
#include <dirent.h>
#include <sqlite3.h>
#include <sodium.h>

static sqlite3* db = NULL;

int db_truncate_keys()
{
	char* err = NULL;
	const char* sql_trunc = "DELETE FROM keys;";

	if (sqlite3_exec(db, sql_trunc, 0, 0, &err) != SQLITE_OK) {
		fprintf(stderr, "sql error: %s\n", err);
		sqlite3_free(err);
		return -1;
	}

	sqlite3_free(err);
	return 0;
}

int db_insert_key(const char* path, const char* filename)
{
	FILE* keyfile = fopen(path, "rb");
	if (keyfile == NULL) {
		perror("fopen");
		return -1;
	}

	char publine[512];
	if (read_to_string(publine, sizeof(publine), keyfile) != 0) {
		return -1;
	}

	u8 pk[crypto_sign_PUBLICKEYBYTES];
	if (parse_ssh_ed25519_publine(publine, pk) != 0) {
		printf("Could not parse publine\n");
		return -1;
	}

	fclose(keyfile);
	sqlite3_stmt* stmt;
	const char* sql = "INSERT INTO keys (username, key) VALUES (?, ?);";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "prepare error: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, filename, -1, SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 2, pk, crypto_sign_PUBLICKEYBYTES, SQLITE_TRANSIENT);

	int step_rc = sqlite3_step(stmt);
	if (step_rc != SQLITE_DONE) {
		fprintf(stderr, "exec error: %s\n", sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	return step_rc == SQLITE_DONE ? 0 : -1;
}

int db_load_keys(const char* directory_path)
{
	if (db_truncate_keys() != 0) {
		fprintf(stderr, "failed to truncate keys table\n");
		return -1;
	}

	DIR* dir = opendir(directory_path);
	if (dir == NULL) {
		perror("opendir");
		return -1;
	}

	char entry_path[PATH_MAX];
	struct dirent* entry;

	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_type == DT_DIR) {
			continue;
		}

		snprintf(entry_path, PATH_MAX, "%s/%s", directory_path, entry->d_name);

		if (db_insert_key(entry_path, entry->d_name) != 0) {
			fprintf(stderr, "failed to load key: %s\n", entry_path);
			continue;
		}
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
			       "username TEXT PRIMARY KEY, "
			       "key BLOB);";

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
