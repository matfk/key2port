#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <core/string.h>
#include <libspa/key.h>
#include <libspa/spa.h>
#include <sodium.h>

#define MIN_PORT 1025
#define MAX_PORT 65535

void print_usage()
{
	printf("usage: <payload>\n");
}

u16 random_port()
{
	return (u16)(rand() % (MAX_PORT - MIN_PORT + 1) + MIN_PORT);
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

	u8 seed[crypto_sign_SEEDBYTES];
	if (parse_openssh_priv_pem(pem, seed) != 0) {
		printf("Could not parse private key pem\n");
		return 1;
	}

	u8 pk[crypto_sign_PUBLICKEYBYTES];
	u8 sk[crypto_sign_SECRETKEYBYTES];
	if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
		printf("Could not sign seed bytes\n");
		return 1;
	}

	struct spa_hdr spa_hdr;
	spa_hdr.magic = SPA_MAGIC;
	spa_hdr.version = SPA_VERSION;
	spa_hdr.flags = 0;
	spa_hdr.client_id = 2026;
	spa_hdr.timestamp = (u32)time(NULL);
	randombytes_buf(spa_hdr.nonce, SPA_NONCE_LEN);

	u16 port = atoi(argv[1]);
	struct spa_payload payload = { 120, port };
	spa_hdr.payload_len = sizeof(payload);

	u8* packet = NULL;
	size_t packet_len = 0;
	if (spa_build_packet(&spa_hdr, (const u8*)&payload, sk, &packet, &packet_len) != 0) {
		fprintf(stderr, "spa build failed\n");
		return 1;
	}

	printf("packet len: %d\n", packet_len);

	// Sending packet
	struct sockaddr_in servaddr;

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	servaddr.sin_port = htons(random_port());
	servaddr.sin_family = AF_INET;

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("sockfd");
		free(packet);
		return 1;
	}

	if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		perror("connect");
		free(packet);
		return 1;
	}

	sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)NULL, sizeof(servaddr));

	free(packet);
	close(sockfd);
	return 0;
}
