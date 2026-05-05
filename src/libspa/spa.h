#ifndef SPA_H
#define SPA_H

#include <stdint.h>
#include <sodium.h>
#include <core/types.h>
#include "spa.h"

#define SPA_MAGIC 0x53504100
#define SPA_VERSION 1
#define SPA_NONCE_LEN 16
#define SPA_HDR_LEN 36
#define SPA_SIG_LEN crypto_sign_BYTES
#define SPA_PAYLOAD_MAX 512

struct spa_hdr {
	u32 magic;
	u16 version;
	u16 flags;
	u32 client_id;
	u32 timestamp;
	u8 nonce[SPA_NONCE_LEN];
	u32 payload_len;
} __attribute__((packed));

struct spa_payload {
	u32 ttl;
	u16 port;
} __attribute__((packed));

int spa_build_packet(const struct spa_hdr* hdr, const u8* payload, const u8* sign_key, u8** out, size_t* out_len);
int spa_parse_hdr(const u8* in, size_t len, struct spa_hdr* hdr);
int spa_verify_packet(const u8* in, size_t len, const u8* pk, struct spa_hdr* hdr);

#endif
