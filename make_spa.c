#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "src/spa.h"
#include <sodium.h>

int main(int argc, char* argv[])
{
	uint8_t pk[crypto_sign_PUBLICKEYBYTES];
	uint8_t sk[crypto_sign_SECRETKEYBYTES];
	crypto_sign_keypair(pk, sk);

	struct spa_hdr spa_hdr;
	spa_hdr.magic = SPA_MAGIC;
	spa_hdr.version = SPA_VERSION;
	spa_hdr.flags = 0;
	spa_hdr.client_id = 2026;
	spa_hdr.timestamp = (uint32_t)time(NULL);
	randombytes_buf(spa_hdr.nonce, SPA_NONCE_LEN);
	char* msg = "hello from spa";
	spa_hdr.payload_len = strlen(msg);

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

	fwrite(packet, packet_len, 1, file);

	//if (spa_verify_packet(packet, packet_len, pk) != 0) {
	//	printf("packed not verified\n");
	//	return 1;
	//}

	printf("packet verified\n");

	// fclose(file);
	free(packet);
	return 0;
}
