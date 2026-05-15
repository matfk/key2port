#include <stdio.h>
#include <string.h>
#include <server/db.h>
#include <server/config.h>
#include <core/string.h>
#include <libspa/key.h>
#include <libspa/spa.h>
#include <dirent.h>
#include <sqlite3.h>
#include <sodium.h>

static sqlite3* db = NULL;

static int db_truncate_keys()
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

int db_select_key(const u8 id[SPA_ID_LEN], u8 pk[crypto_sign_PUBLICKEYBYTES])
{
	sqlite3_stmt* stmt;
	const char* sql = "SELECT key FROM keys WHERE id = ?;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		return -1;
	}

	sqlite3_bind_blob(stmt, 1, id, SPA_ID_LEN, SQLITE_STATIC);

	int step_rc = sqlite3_step(stmt);
	if (step_rc == SQLITE_ROW) {
		const void* blob = sqlite3_column_blob(stmt, 0);
		int bytes = sqlite3_column_bytes(stmt, 0);

		if (bytes == crypto_sign_PUBLICKEYBYTES) {
			memcpy(pk, blob, bytes);
		}

		step_rc = 0;
	} else if (step_rc == SQLITE_DONE) {
		// not found
		step_rc = -1;
	} else {
		step_rc = -2;
	}

	sqlite3_finalize(stmt);
	return step_rc;
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
		fclose(keyfile);
		return -1;
	}

	u8 pk[crypto_sign_PUBLICKEYBYTES];
	if (parse_ssh_ed25519_publine(publine, pk) != 0) {
		printf("Could not parse publine\n");
		fclose(keyfile);
		return -1;
	}

	u8 id[SPA_ID_LEN];
	strnhash(id, SPA_ID_LEN, filename);

	fclose(keyfile);
	sqlite3_stmt* stmt;
	const char* sql = "INSERT INTO keys (id, name, key) VALUES (?, ?, ?);";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "prepare error: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_blob(stmt, 1, id, SPA_ID_LEN, SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, filename, -1, SQLITE_STATIC);
	sqlite3_bind_blob(stmt, 3, pk, crypto_sign_PUBLICKEYBYTES, SQLITE_TRANSIENT);

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

int db_nonce_seen(const u8 nonce[SPA_NONCE_LEN])
{
	sqlite3_stmt* stmt;
	const char* sql = "SELECT 1 FROM seen WHERE nonce = ? LIMIT 1";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "prepare error: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_blob(stmt, 1, nonce, SPA_NONCE_LEN, SQLITE_TRANSIENT);
	int step_rc = sqlite3_step(stmt);
	int exists = 0;

	if (step_rc == SQLITE_ROW) {
		exists = 1;
	} else if (step_rc == SQLITE_DONE) {
		exists = 0;
	} else {
		fprintf(stderr, "exec error: %s\n", sqlite3_errmsg(db));
		exists = -1;
	}

	sqlite3_finalize(stmt);
	return exists;
}

int db_insert_seen(const u8 nonce[SPA_NONCE_LEN], u32 timestamp)
{
	sqlite3_stmt* stmt;
	const char* sql = "INSERT INTO seen (nonce, timestamp) VALUES (?, ?);";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "prepare error: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_blob(stmt, 1, nonce, SPA_NONCE_LEN, SQLITE_TRANSIENT);
	sqlite3_bind_int64(stmt, 2, (u64)timestamp);

	int step_rc = sqlite3_step(stmt);
	if (step_rc != SQLITE_DONE) {
		fprintf(stderr, "exec error: %s\n", sqlite3_errmsg(db));
	}

	sqlite3_finalize(stmt);
	return step_rc == SQLITE_DONE ? 0 : -1;
}

int db_init()
{
	if (db) {
		return 0;
	}

	const k2pconfig* config = config_get();

	if (sqlite3_open(config->sqlite_db, &db) != SQLITE_OK) {
		fprintf(stderr, "failed to open database: %s\n", sqlite3_errmsg(db));
		return -1;
	}

	char* err = NULL;
	const char* sql_seen = "CREATE TABLE IF NOT EXISTS seen ("
			       "id INTEGER PRIMARY KEY AUTOINCREMENT, "
			       "nonce BLOB NOT NULL, "
			       "timestamp INTEGER NOT NULL);";

	if (sqlite3_exec(db, sql_seen, 0, 0, &err) != SQLITE_OK) {
		fprintf(stderr, "sql error: %s\n", err);
		sqlite3_free(err);
		return -1;
	}

	const char* sql_seen_idx = "CREATE UNIQUE INDEX IF NOT EXISTS ix_seen_nonce ON seen(nonce);";

	if (sqlite3_exec(db, sql_seen_idx, 0, 0, &err) != SQLITE_OK) {
		fprintf(stderr, "sql error: %s\n", err);
		sqlite3_free(err);
		return -1;
	}

	const char* sql_keys = "CREATE TABLE IF NOT EXISTS keys ("
			       "id BLOB PRIMARY KEY, "
			       "name TEXT, "
			       "key BLOB);";

	if (sqlite3_exec(db, sql_keys, 0, 0, &err) != SQLITE_OK) {
		fprintf(stderr, "sql error: %s\n", err);
		sqlite3_free(err);
		return -1;
	}

	if (db_load_keys(config->keys) != 0) {
		fprintf(stderr, "failed to load keys\n");
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
