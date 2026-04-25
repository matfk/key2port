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
#include "spa.h"

#define SNAP_LEN 1518
#define ETHER_LEN 14
#define ETHER_ADDR_LEN 6
#define IP_LEN 20
#define BUFFER_LEN 256
#define UDP_LEN 8

static atomic_int count = 0;

struct ethernet_hdr {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	uint16_t ether_type;
} __attribute__((packed));

struct ip_hdr {
	u_char ip_vhl;
	u_char ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	u_char ip_ttl;
	u_char ip_p;
	uint16_t ip_sum;
	struct in_addr ip_src, ip_dst;
} __attribute__((packed));

struct udp_hdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} __attribute__((packed));

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

static int ethernet_parse_hdr(const u_char* packet, size_t len, struct ethernet_hdr* hdr)
{
	if (len < ETHER_LEN)
		return 1;

	memcpy(hdr, packet, sizeof(*hdr));
	hdr->ether_type = ntohs(hdr->ether_type);

	if (hdr->ether_type != 0x0800)
		return 1;

	return 0;
}

static int ip_parse_hdr(const u_char* packet, size_t len, struct ip_hdr* hdr, int* out_ip_len)
{
	if (len < IP_LEN)
		return 1;

	memcpy(hdr, packet, IP_LEN);
	if (IP_V(hdr) != 4)
		return 1;

	int size_ip = IP_HL(hdr) * 4;
	if (size_ip < 20)
		return 1;

	if (len < size_ip)
		return 1;

	hdr->ip_len = ntohs(hdr->ip_len);
	hdr->ip_id = ntohs(hdr->ip_id);
	hdr->ip_off = ntohs(hdr->ip_off);
	hdr->ip_sum = ntohs(hdr->ip_sum);

	*out_ip_len = size_ip;
	return 0;
}

static int udp_parse_hdr(const u_char* packet, size_t len, struct udp_hdr* hdr)
{
	if (len < UDP_LEN)
		return 1;

	memcpy(hdr, packet, UDP_LEN);
	hdr->source = ntohs(hdr->source);
	hdr->dest = ntohs(hdr->dest);
	hdr->len = ntohs(hdr->len);
	hdr->check = ntohs(hdr->check);

	return 0;
}

static void got_packet(uint8_t* args, const struct pcap_pkthdr* header, const uint8_t* packet)
{
	int curr_count = atomic_fetch_add_explicit(&count, 1, memory_order_relaxed);
	printf("got packet: %d\n", curr_count);

	uint8_t* p = packet;
	struct ethernet_hdr eth;
	struct ip_hdr ip;
	int ip_len;
	struct udp_hdr udp;
	struct spa_hdr spa;

	if (ethernet_parse_hdr(p, header->caplen, &eth) != 0)
		return;
	p += ETHER_LEN;
	printf("parsed eth hdr\n");

	if (ip_parse_hdr(p, header->caplen - ETHER_LEN, &ip, &ip_len) != 0)
		return;
	p += ip_len;
	printf("parsed ip hdr, header len=%d\n", ip_len);

	if (udp_parse_hdr(p, header->caplen - ETHER_LEN - ip_len, &udp) != 0)
		return;

	p += UDP_LEN;
	printf("parsed udp hdr, dst port=%u\n", udp.dest);

	if (spa_parse_hdr(p, header->caplen - ETHER_LEN - ip_len - UDP_LEN, &spa) != 0)
		return;

	p += SPA_HDR_LEN;
	printf("parsed spa header, magic=0x%08x version=%d flags=0x%02x client_id=%u timestamp=%u payload-len=%u\n", spa.magic, spa.version,
	       spa.flags, spa.client_id, spa.timestamp, spa.payload_len);

	size_t spa_off = ETHER_LEN + ip_len + UDP_LEN;
	size_t payload_off = spa_off + sizeof(struct spa_hdr);

	if (spa.payload_len >= BUFFER_LEN) {
		fprintf(stderr, "spa payload too large: %u\n", spa.payload_len);
		return;
	}

	if (header->caplen < payload_off + spa.payload_len) {
		fprintf(stderr, "truncated: caplen=%u need=%zu\n", header->caplen, payload_off + spa.payload_len);
		return;
	}

	char payload[BUFFER_LEN];
	if (spa.payload_len > 0)
		memcpy(payload, packet + payload_off, spa.payload_len);
	payload[spa.payload_len] = '\0';
	printf("payload: %s\n", payload);
}

int main(int argc, char* argv[])
{
	char* dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	char filter_exp[] = "udp and udp[8:4] = 0x53504100";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_if_t* devices = NULL;

	if (argc == 2) {
		dev = argv[1];
	} else {
		if (pcap_findalldevs(&devices, errbuf) == -1) {
			fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
		if (devices == NULL) {
			fprintf(stderr, "no devices found\n");
			exit(EXIT_FAILURE);
		}
		dev = devices->name;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		net = 0;
		mask = 0;
	}

	printf("Device: %s\n", dev);
	printf("Filter: %s\n", filter_exp);

	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not Ethernet\n", dev);
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
		pcap_freecode(&fp);
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 0, got_packet, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);
	pcap_freealldevs(devices);
	return 0;
}
