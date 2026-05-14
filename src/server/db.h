#ifndef DB_H
#define DB_H

#include <core/types.h>
#include <libspa/spa.h>

int db_init();
int db_insert_seen(const char nonce[SPA_NONCE_LEN], u32 timestamp);
void db_close();

#endif
