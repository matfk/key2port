#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "src/spa.h"
#include "src/key.h"
#include "src/string.h"
#include <sodium.h>

int main(int argc, char* argv[])
{
	char* pem = read_to_string("key", NULL);
	if (pem == NULL)
		return 1;

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
	char* msg = "hello from spa";
	spa_hdr.payload_len = strlen(msg);

	printf("Length: %d", sizeof(spa_hdr) + strlen(msg));

	uint8_t* packet = NULL;
	size_t packet_len = 0;
	if (spa_build_packet(&spa_hdr, msg, sk, &packet, &packet_len) != 0) {
		fprintf(stderr, "spa build failed\n");
		return 1;
	}

	FILE* file = fopen("pkt.bin", "wb");
	if (!file) {
		perror("fopen");
		return 1;
	}

	char* publine = read_to_string("key.pub", NULL);
	if (publine == NULL) {
		perror("read_to_string");
		return 1;
	}

	uint8_t pk2[32];
	if (parse_ssh_ed25519_publine(publine, pk2) != 0) {
		printf("parse pk");
		return 1;
	}

	fwrite(packet, packet_len, 1, file);

	if (spa_verify_packet(packet, packet_len, pk2) != 0) {
		printf("packed not verified\n");
		return 1;
	}

	printf("packet verified\n");

	fclose(file);
	free(pem);
	free(publine);
	free(packet);
	return 0;
}
