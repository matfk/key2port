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
#include <getopt.h>

#define MIN_PORT 1025
#define MAX_PORT 65535

// clang-format off
struct option long_options[] = {
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
	{"p", required_argument, 0, 'p'},
	{"ttl", required_argument, 0, 't'},
	{0, 0, 0, 0}
};
// clang-format on

void print_usage()
{
	printf("Usage: <target> [OPTIONS]\n");
	printf("Options:\n");
	printf("  -h, --help         Show this help message and exit\n");
	printf("  -v, --version      Show version info and exit\n");
	printf("  -p, --port         Port\n");
	printf("  --ttl              Time To Live\n");
}

void print_version()
{
	printf("Occultus v0.1\n");
}

u16 random_port()
{
	return (u16)(rand() % (MAX_PORT - MIN_PORT + 1) + MIN_PORT);
}

int parse_pem_sk(const char* path, u8 sk[crypto_sign_SECRETKEYBYTES])
{
	FILE* sk_file = fopen(path, "rb");
	if (sk_file == NULL) {
		perror("fopen");
		return -1;
	}

	char pem[4096];
	if (read_to_string(pem, sizeof(pem), sk_file) != 0) {
		perror("read_to_string");
		return -1;
	}

	fclose(sk_file);

	u8 seed[crypto_sign_SEEDBYTES];
	if (parse_openssh_priv_pem(pem, seed) != 0) {
		fprintf(stderr, "parse_pem_sk: failed to parse pem\n");
		return -1;
	}

	u8 pk[crypto_sign_PUBLICKEYBYTES];
	if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
		fprintf(stderr, "parse_pem_sk: failed to sign seed keypair\n");
		return -1;
	}

	return 0;
}

struct spa_hdr create_packet_hdr(u32 client_id, u16 flags)
{
	struct spa_hdr spa_hdr;
	spa_hdr.magic = SPA_MAGIC;
	spa_hdr.version = SPA_VERSION;
	spa_hdr.flags = flags;
	spa_hdr.client_id = client_id;
	spa_hdr.timestamp = (u32)time(NULL);
	randombytes_buf(spa_hdr.nonce, SPA_NONCE_LEN);
	return spa_hdr;
}

int create_packet(u16 port, u32 ttl, u32 client_id, u16 flags, u8 sk[crypto_sign_SECRETKEYBYTES], u8** packet, size_t* packet_len)
{
	struct spa_hdr hdr = create_packet_hdr(client_id, flags);
	struct spa_payload payload = { ttl, port };
	hdr.payload_len = sizeof(payload);

	if (spa_build_packet(&hdr, (const u8*)&payload, sk, packet, packet_len) != 0) {
		fprintf(stderr, "spa build failed\n");
		return -1;
	}

	return 0;
}

int send_udp_packet(const char* target, const u8* packet, size_t packet_len)
{
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));

	servaddr.sin_addr.s_addr = inet_addr(target);
	servaddr.sin_port = htons(random_port());
	servaddr.sin_family = AF_INET;

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("sockfd");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		perror("connect");
		return -1;
	}

	sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)NULL, sizeof(servaddr));
	close(sockfd);

	return 0;
}

int main(int argc, char* argv[])
{
	if (argc < 2) {
		print_usage();
		return 0;
	}

	u32 client_id = 2000;
	u16 port = 4444;
	u32 ttl = 120;
	int opt;

	while ((opt = getopt_long(argc, argv, "hvp:t:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			return 0;
		case 'v':
			print_version();
			return 0;
		case 'p':
			port = atoi(optarg);
			break;
		case 't':
			ttl = atoi(optarg);
			break;
		}
	}

	char* target = argv[optind];
	if (target == NULL) {
		print_usage();
		return 1;
	}

	u8 sk[crypto_sign_SECRETKEYBYTES];
	if (parse_pem_sk("key", sk) != 0)
		return 1;

	u8* packet = NULL;
	size_t packet_len = 0;

	if (create_packet(port, ttl, client_id, 0, sk, &packet, &packet_len) != 0)
		return 1;

	if (send_udp_packet(target, packet, packet_len) != 0)
		return 1;

	free(packet);
	return 0;
}
