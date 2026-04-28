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
#include "key.h"
#include "types.h"
#include "string.h"

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
	u16 ether_type;
} __attribute__((packed));

struct ip_hdr {
	u_char ip_vhl;
	u_char ip_tos;
	u16 ip_len;
	u16 ip_id;
	u16 ip_off;
	u_char ip_ttl;
	u_char ip_p;
	u16 ip_sum;
	struct in_addr ip_src, ip_dst;
} __attribute__((packed));

struct udp_hdr {
	u16 source;
	u16 dest;
	u16 len;
	u16 check;
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
	if (size_ip < IP_LEN)
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

static int parse_hdrs(const u8* packet, size_t packet_len)
{
	u8* p = packet;
	int ip_len;

	struct ethernet_hdr eth;
	struct ip_hdr ip;
	struct udp_hdr udp;

	if (ethernet_parse_hdr(p, packet_len, &eth) != 0)
		return -1;

	p += ETHER_LEN;
	packet_len - ETHER_LEN;

	if (ip_parse_hdr(p, packet_len, &ip, &ip_len) != 0)
		return -1;

	p += ip_len;
	packet_len - ip_len;

	if (udp_parse_hdr(p, packet_len, &udp) != 0)
		return -1;

	p += UDP_LEN;

	return (int)(p - packet);
}

static void got_packet(u8* args, const struct pcap_pkthdr* header, const u8* packet)
{
	int curr_count = atomic_fetch_add_explicit(&count, 1, memory_order_relaxed);
	printf("Packet Count: %d\n", curr_count);

	int parsed_len = parse_hdrs(packet, header->caplen);
	if (parsed_len == -1) {
		return;
	}

	int len = header->caplen - parsed_len;
	printf("Header Length: %d\n", parsed_len);
	printf("SPA length: %d\n", len);
	printf("Total Length: %d\n", header->caplen);

	u8 pk[crypto_sign_PUBLICKEYBYTES];
	char* publine = read_to_string("key.pub", NULL);
	if (publine == NULL)
		return;

	printf("publine: %s\n", publine);

	if (parse_ssh_ed25519_publine(publine, pk) != 0) {
		printf("Could not parse publine\n");
		return;
	}

	u8* spa = packet + parsed_len;
	if (spa_verify_packet(spa, len, pk) != 0) {
		printf("Packet Not verified\n");
		return;
	}

	printf("Packed Verified\n");
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
