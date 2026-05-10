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
#include <server/spsc.h>
#include <server/packet_parser.h>
#include <server/worker.h>

typedef struct {
	struct pcap_pkthdr header;
	u8 packet[];
} capture_event;

typedef struct {
	pthread_t tid;
	struct spsc_ring ring;
} worker_t;

static atomic_uint count = 0;

static worker_t* workers = NULL;
static size_t workers_count = 0;

void* worker(void* arg)
{
	int i = (int)(intptr_t)arg;
	printf("starting worker: %d\n", i);

	while (1) {
		capture_event* event = (capture_event*)spsc_pop(&workers[i].ring);
		printf("Worker %d\n", i);

		struct pcap_pkthdr* header = &event->header;
		u8* packet = event->packet;

		struct ethernet_hdr eth_hdr;
		struct ip_hdr ip_hdr;
		struct udp_hdr udp_hdr;
		struct spa_hdr hdr;

		int parsed_len = parse_hdrs(packet, header->caplen, &eth_hdr, &ip_hdr, &udp_hdr);
		if (parsed_len == -1) {
			free(event);
			continue;
		}

		int len = header->caplen - parsed_len;

		// TODO: REMOVE
		FILE* keyfile = fopen("key.pub", "rb");
		if (keyfile == NULL) {
			free(event);
			continue;
		}

		char publine[512];
		if (read_to_string(publine, sizeof(publine), keyfile) != 0) {
			free(event);
			continue;
		}

		u8 pk[crypto_sign_PUBLICKEYBYTES];
		if (parse_ssh_ed25519_publine(publine, pk) != 0) {
			printf("Could not parse publine\n");
			free(event);
			continue;
		}

		u8* spa = packet + parsed_len;
		if (spa_verify_packet(spa, len, pk, &hdr) != 0) {
			printf("Packet Not verified\n");
			free(event);
			continue;
		}

		struct spa_payload payload;
		if ((len - SPA_HDR_LEN) < sizeof(payload)) {
			free(event);
			continue;
		}

		memcpy(&payload, spa + SPA_HDR_LEN, sizeof(payload));

		char ip_addr[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &ip_hdr.ip_src, ip_addr, INET_ADDRSTRLEN) == NULL) {
			free(event);
			continue;
		}

		printf("source=%s ttl=%d port=%d\n", ip_addr, payload.ttl, payload.port);

		if (nft_add_ipv4(ip_addr, payload.port, payload.ttl) != 0) {
			free(event);
			continue;
		}

		free(event);
	}
}

void worker_dispatch(u8* args, const struct pcap_pkthdr* header, const u8* packet)
{
	u32 curr_count = atomic_fetch_add_explicit(&count, 1, memory_order_relaxed);
	u32 worker_idx = curr_count % workers_count;
	printf("Packet Count: %d\n", curr_count);

	capture_event* event = malloc(sizeof(capture_event) + header->caplen);
	if (event == NULL)
		return;

	event->header = *header;
	memcpy(event->packet, packet, header->caplen);

	if (spsc_push(&workers[worker_idx].ring, event) != 0) {
		free(event);
	}
}

void worker_pool_init(size_t n)
{
	workers_count = n;
	workers = (worker_t*)malloc(sizeof(worker_t) * n);

	for (int i = 0; i < n; i++) {
		worker_t w;
		pthread_create(&w.tid, NULL, worker, (void*)(intptr_t)i);
		spsc_init(&w.ring);
		workers[i] = w;
	}
}

void worker_pool_join()
{
	if (workers == NULL)
		return;

	for (int i = 0; i < workers_count; i++) {
		pthread_join(workers[i].tid, NULL);
	}

	free(workers);
}
