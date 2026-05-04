#include "spa.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <core/types.h>

size_t spa_serialize_hdr(const struct spa_hdr* hdr, u8* out)
{
	u8* p = out;
	u32 magic = htonl(hdr->magic);
	memcpy(p, &magic, 4);
	p += 4;

	u16 version = htons(hdr->version);
	memcpy(p, &version, 2);
	p += 2;

	u16 flags = htons(hdr->flags);
	memcpy(p, &flags, 2);
	p += 2;

	u32 client_id = htonl(hdr->client_id);
	memcpy(p, &client_id, 4);
	p += 4;

	u32 timestamp = htonl(hdr->timestamp);
	memcpy(p, &timestamp, 4);
	p += 4;

	memcpy(p, hdr->nonce, SPA_NONCE_LEN);
	p += SPA_NONCE_LEN;

	u32 payload_len = htonl(hdr->payload_len);
	memcpy(p, &payload_len, 4);
	p += 4;

	return (size_t)(p - out);
}

int spa_parse_hdr(const u8* in, size_t len, struct spa_hdr* hdr)
{
	if (len < SPA_HDR_LEN)
		return -1;

	memcpy(hdr, in, SPA_HDR_LEN);
	hdr->magic = ntohl(hdr->magic);
	hdr->version = ntohs(hdr->version);
	hdr->flags = ntohs(hdr->flags);
	hdr->client_id = ntohl(hdr->client_id);
	hdr->timestamp = ntohl(hdr->timestamp);
	hdr->payload_len = ntohl(hdr->payload_len);

	return 0;
}

int spa_build_packet(const struct spa_hdr* hdr, const u8* payload, const u8* sign_key, u8** out, size_t* out_len)
{
	u8 hdr_buffer[SPA_HDR_LEN];
	size_t hdr_size = spa_serialize_hdr(hdr, hdr_buffer);

	size_t total = hdr_size + hdr->payload_len + SPA_SIG_LEN;
	u8* buffer = malloc(total);
	if (buffer == NULL)
		return -1;

	u8* p = buffer;
	memcpy(p, hdr_buffer, hdr_size);
	p += hdr_size;

	if (hdr->payload_len) {
		memcpy(p, payload, hdr->payload_len);
		p += hdr->payload_len;
	}

	u8* sig = p;
	if (crypto_sign_detached(sig, NULL, buffer, hdr_size + hdr->payload_len, sign_key) != 0) {
		free(buffer);
		return -1;
	}

	*out = buffer;
	*out_len = total;
	return 0;
}

int spa_verify_packet(const u8* in, size_t len, const u8* pk, struct spa_hdr* hdr)
{
	if (len < SPA_HDR_LEN + SPA_SIG_LEN)
		return -1;

	if (spa_parse_hdr(in, len, hdr) != 0)
		return -1;

	if (hdr->magic != SPA_MAGIC)
		return -1;

	if (hdr->version != SPA_VERSION)
		return -1;

	if (hdr->payload_len > SPA_PAYLOAD_MAX)
		return -1;

	size_t total_len = SPA_HDR_LEN + hdr->payload_len + SPA_SIG_LEN;
	if (len < total_len)
		return -1;

	u8* sig = in + SPA_HDR_LEN + hdr->payload_len;
	if (crypto_sign_verify_detached(sig, in, SPA_HDR_LEN + hdr->payload_len, pk) != 0)
		return -1;

	// TODO: enforce time, nonce and flags policies

	return 0;
}
