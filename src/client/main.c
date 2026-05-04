#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <core/string.h>
#include <libspa/key.h>
#include <libspa/spa.h>
#include <sodium.h>

void print_usage()
{
	printf("usage: <payload>\n");
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		print_usage();
		return 0;
	}

	FILE* sk_file = fopen("key", "rb");
	if (sk_file == NULL) {
		perror("fopen");
		return 1;
	}

	char pem[4096];
	if (read_to_string(pem, sizeof(pem), sk_file) != 0) {
		perror("read_to_string");
		return 1;
	}

	printf("pem: %s\n", pem);

	uint8_t seed[crypto_sign_SEEDBYTES];
	if (parse_openssh_priv_pem(pem, seed) != 0) {
		printf("Could not parse private key pem\n");
		return 1;
	}

	uint8_t pk[crypto_sign_PUBLICKEYBYTES];
	uint8_t sk[crypto_sign_SECRETKEYBYTES];
	if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
		printf("Could not sign seed bytes\n");
		return 1;
	}

	struct spa_hdr spa_hdr;
	spa_hdr.magic = SPA_MAGIC;
	spa_hdr.version = SPA_VERSION;
	spa_hdr.flags = 0;
	spa_hdr.client_id = 2026;
	spa_hdr.timestamp = (uint32_t)time(NULL);
	randombytes_buf(spa_hdr.nonce, SPA_NONCE_LEN);
	char* msg = argv[1];
	spa_hdr.payload_len = strlen(msg);

	uint8_t* packet = NULL;
	size_t packet_len = 0;
	if (spa_build_packet(&spa_hdr, msg, sk, &packet, &packet_len) != 0) {
		fprintf(stderr, "spa build failed\n");
		return 1;
	}

	printf("packet len: %d\n", packet_len);

	free(packet);
	return 0;
}
