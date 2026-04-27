#ifndef SPA_H
#define SPA_H

#include <stdint.h>
#include <sodium.h>

#define SPA_MAGIC 0x53504100
#define SPA_VERSION 1
#define SPA_NONCE_LEN 16
#define SPA_HDR_LEN 36
#define SPA_SIG_LEN crypto_sign_BYTES
#define SPA_PAYLOAD_MAX 512

struct spa_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t flags;
	uint32_t client_id;
	uint32_t timestamp;
	uint8_t nonce[SPA_NONCE_LEN];
	uint32_t payload_len;
} __attribute__((packed));

int spa_build_packet(const struct spa_hdr* hdr, const uint8_t* payload, const uint8_t* sign_key, uint8_t** out, size_t* out_len);
int spa_parse_hdr(const uint8_t* in, size_t len, struct spa_hdr* hdr);
int spa_verify_packet(const uint8_t* in, size_t len, const uint8_t* pk);

#endif
