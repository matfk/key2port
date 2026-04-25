#include "spa.h"
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

size_t spa_serialize_hdr(const struct spa_hdr* hdr, uint8_t* out)
{
	uint8_t* p = out;
	uint32_t magic = htonl(hdr->magic);
	memcpy(p, &magic, 4);
	p += 4;

	*p++ = hdr->version;
	*p++ = hdr->flags;

	uint32_t client_id = htonl(hdr->client_id);
	memcpy(p, &client_id, 4);
	p += 4;

	uint32_t timestamp = htonl(hdr->timestamp);
	memcpy(p, &timestamp, 4);
	p += 4;

	memcpy(p, hdr->nonce, SPA_NONCE_LEN);
	p += SPA_NONCE_LEN;

	uint32_t payload_len = htonl(hdr->payload_len);
	memcpy(p, &payload_len, 4);
	p += 4;

	return (size_t)(p - out);
}

int spa_parse_hdr(const uint8_t* in, size_t len, struct spa_hdr* hdr)
{
	if (len < SPA_HDR_LEN)
		return -1;

	uint8_t* p = in;

	uint32_t magic;
	memcpy(&magic, p, 4);
	hdr->magic = ntohl(magic);
	p += 4;

	hdr->version = *p++;
	hdr->flags = *p++;

	uint32_t client_id;
	memcpy(&client_id, p, 4);
	hdr->client_id = ntohl(client_id);
	p += 4;

	uint32_t timestamp;
	memcpy(&timestamp, p, 4);
	hdr->timestamp = ntohl(timestamp);
	p += 4;

	memcpy(hdr->nonce, p, SPA_NONCE_LEN);
	p += SPA_NONCE_LEN;

	uint32_t payload_len;
	memcpy(&payload_len, p, 4);
	hdr->payload_len = ntohl(payload_len);
	p += 4;

	return 0;
}

int spa_build_packet(const struct spa_hdr* hdr, const uint8_t* payload, const uint8_t* sign_key, uint8_t** out, size_t* out_len)
{
	uint8_t hdr_buffer[SPA_HDR_LEN];
	size_t hdr_size = spa_serialize_hdr(hdr, hdr_buffer);

	size_t total = hdr_size + hdr->payload_len + SPA_SIG_LEN;
	uint8_t* buffer = malloc(total);
	if (buffer == NULL)
		return -1;

	uint8_t* p = buffer;
	memcpy(p, hdr_buffer, hdr_size);
	p += hdr_size;

	if (hdr->payload_len) {
		memcpy(p, payload, hdr->payload_len);
		p += hdr->payload_len;
	}

	uint8_t* sig = p;
	if (crypto_sign_detached(sig, NULL, buffer, hdr_size + hdr->payload_len, sign_key) != 0) {
		free(buffer);
		return -1;
	}

	*out = buffer;
	*out_len = total;
	return 0;
}

int spa_verify_packet(const uint8_t* in, size_t len, const uint8_t* pk)
{
	if (len < SPA_HDR_LEN + SPA_SIG_LEN)
		return -1;

	struct spa_hdr hdr;
	if (spa_parse_hdr(in, len, &hdr) != 0)
		return -1;

	if (hdr.magic != SPA_MAGIC)
		return -1;

	if (hdr.version != SPA_VERSION)
		return -1;

	size_t total_len = SPA_HDR_LEN + hdr.payload_len + SPA_SIG_LEN;
	if (len < total_len)
		return -1;

	uint8_t* sig = in + SPA_HDR_LEN + hdr.payload_len;
	if (crypto_sign_verify_detached(sig, in, SPA_HDR_LEN + hdr.payload_len, pk) != 0)
		return -1;

	// TODO: enforce time, nonce and flags policies

	return 0;
}
