#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <time.h>
#include <sodium.h>
#include <core/string.h>
#include <core/types.h>
#include <libspa/spa.h>
#include <libspa/key.h>
#include <pthread.h>
#include <server/nft.h>
#include <server/packet_parser.h>
#include <server/capture.h>
#include <server/config.h>
#include <server/db.h>
#include <core/log.h>

#define CONFIG_PATH "/etc/k2p/k2p.conf"

int main(void)
{
	char filter_exp[] = "udp and udp[8:4] = 0x53504100";
	cap_ctx cap_ctx;

	if (config_load(CONFIG_PATH) != 0) {
		return 1;
	}

	k2pconfig* config = config_get();

	if (logs_open(config->log_auth, config->log_error) != 0) {
		return 1;
	}

	if (cap_ctx_init(&cap_ctx, config->interface, filter_exp) != 0) {
		return 1;
	}

	if (db_init() != 0) {
		return 1;
	}

	if (nft_ctx_init() != 0) {
		return 1;
	}

	pcap_t* handle = cap_ctx_get_handle(&cap_ctx);
	struct pcap_pkthdr* header;
	const u8* packet;

	while (pcap_next_ex(handle, &header, &packet) >= 0) {
		struct ethernet_hdr eth_hdr;
		struct ip_hdr ip_hdr;
		struct udp_hdr udp_hdr;
		struct spa_hdr hdr;

		int parsed_len = parse_hdrs(packet, header->caplen, &eth_hdr, &ip_hdr, &udp_hdr);
		if (parsed_len == -1) {
			continue;
		}

		int len = header->caplen - parsed_len;
		const u8* spa = packet + parsed_len;

		if (spa_parse_hdr(spa, len, &hdr) != 0)
			continue;

		u8 pk[crypto_sign_PUBLICKEYBYTES];
		if (db_select_key(hdr.id, pk) != 0) {
			continue;
		}

		if (spa_verify_packet(spa, len, pk, &hdr) != 0) {
			continue;
		}

		if (db_nonce_seen(hdr.nonce) != 0) {
			continue;
		}

		if (db_insert_seen(hdr.nonce, hdr.timestamp) != 0) {
			LOG_ERROR("faled to insert seen\n");
			continue;
		}

		u32 now_ts = (u32)time(NULL);
		u32 packet_ts = hdr.timestamp;

		if (packet_ts < (now_ts - config->replay_window) || packet_ts > (now_ts + config->replay_window)) {
			continue;
		}

		struct spa_payload payload;
		if ((u64)(len - SPA_HDR_LEN) < sizeof(payload)) {
			continue;
		}

		memcpy(&payload, spa + SPA_HDR_LEN, sizeof(payload));

		char ip_addr[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &ip_hdr.ip_src, ip_addr, INET_ADDRSTRLEN) == NULL) {
			continue;
		}

		if (nft_allow_port(payload.port, ip_addr, payload.ttl) != 0) {
			continue;
		}

		LOG_AUTH("[%d] status=SUCCESS allow=%s:%d ttl=%d", now_ts, ip_addr, payload.port, payload.ttl);
	}

	cap_ctx_free(&cap_ctx);
	nft_free();
	db_close();
	return 0;
}
