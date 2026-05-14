#ifndef DB_H
#define DB_H

#include <core/types.h>
#include <libspa/spa.h>

int db_init();
int db_select_key(const u8 id[SPA_ID_LEN], u8 pk[crypto_sign_PUBLICKEYBYTES]);
int db_nonce_seen(const u8 nonce[SPA_NONCE_LEN]);
int db_insert_seen(const u8 nonce[SPA_NONCE_LEN], u32 timestamp);
void db_close();

#endif
