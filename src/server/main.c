#define _DEFAULT_SOURCE
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

int main(int argc, char* argv[])
{
	char filter_exp[] = "udp and udp[8:4] = 0x53504100";
	char* dev = argv[1];

	if (config_load("conf/key2port.conf") != 0) {
		return 1;
	}

	if (pcap_cap_init(dev, filter_exp) != 0) {
		return 1;
	}

	if (nft_ctx_init() != 0) {
		return 1;
	}

	pcap_t* handle = pcap_get_handle();
	struct pcap_pkthdr* header;
	const u8* packet;

	while (pcap_next_ex(handle, &header, &packet) >= 0) {
		struct ethernet_hdr eth_hdr;
		struct ip_hdr ip_hdr;
		struct udp_hdr udp_hdr;
		struct spa_hdr hdr;

		int parsed_len = parse_hdrs(packet, header->caplen, &eth_hdr, &ip_hdr, &udp_hdr);
		if (parsed_len == -1) {
			return 1;
		}

		int len = header->caplen - parsed_len;

		// TODO: REMOVE
		FILE* keyfile = fopen("key.pub", "rb");
		if (keyfile == NULL) {
			return 1;
		}

		char publine[512];
		if (read_to_string(publine, sizeof(publine), keyfile) != 0) {
			return 1;
		}

		u8 pk[crypto_sign_PUBLICKEYBYTES];
		if (parse_ssh_ed25519_publine(publine, pk) != 0) {
			printf("Could not parse publine\n");
			return 1;
		}

		u8* spa = packet + parsed_len;
		if (spa_verify_packet(spa, len, pk, &hdr) != 0) {
			printf("Packet Not verified\n");
			return 1;
		}

		struct spa_payload payload;
		if ((len - SPA_HDR_LEN) < sizeof(payload)) {
			return 1;
		}

		memcpy(&payload, spa + SPA_HDR_LEN, sizeof(payload));

		char ip_addr[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &ip_hdr.ip_src, ip_addr, INET_ADDRSTRLEN) == NULL) {
			return 1;
		}

		printf("source=%s ttl=%d port=%d\n", ip_addr, payload.ttl, payload.port);

		if (nft_add_ipv4(ip_addr, payload.port, payload.ttl) != 0) {
			return 1;
		}
	}

	pcap_cap_free();
	nft_free();
	return 0;
}
