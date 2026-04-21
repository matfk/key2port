#define _DEFAULT_SOURCE
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#define SNAP_LEN 1518
#define ETHER_LEN 14
#define ETHER_ADDR_LEN 6

static atomic_int count = 0;

struct ethernet_hdr {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
} __attribute__((packed));

struct ip_hdr {
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src, ip_dst;
} __attribute__((packed));

#define IP_V(ip) (((ip)->ip_vhl) >> 4)

static int parse_ethernet_hdr(const u_char* packet, bpf_u_int32 caplen, struct ethernet_hdr* hdr)
{
	if (caplen < ETHER_LEN)
		return 1;

	memcpy(hdr, packet, sizeof(struct ethernet_hdr));
	if (hdr == NULL)
		return 1;

	hdr->ether_type = ntohs(hdr->ether_type);

	if (hdr->ether_type != 0x800)
		return 1;

	return 0;
}

static int parse_ip_hdr(const u_char* packet, bpf_u_int32 caplen, struct ip_hdr* hdr)
{
	if (caplen < ETHER_LEN + sizeof(struct ip_hdr))
		return 1;

	memcpy(hdr, packet + ETHER_LEN, sizeof(struct ip_hdr));
	if (hdr == NULL)
		return 1;

	if (IP_V(hdr) != 4) {
		printf("not ipv4: \n", IP_V(hdr));
		return 1;
	}

	hdr->ip_len = ntohs(hdr->ip_len);
	hdr->ip_id = ntohs(hdr->ip_id);
	hdr->ip_off = ntohs(hdr->ip_off);
	hdr->ip_sum = ntohs(hdr->ip_sum);

	return 0;
}

static void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	int curr_count = atomic_fetch_add_explicit(&count, 1, memory_order_relaxed);
	printf("got packet: %d\n", curr_count);

	struct ethernet_hdr eth_hdr;
	if (parse_ethernet_hdr(packet, header->caplen, &eth_hdr) == 0)
		printf("parsed eth hdr\n");

	struct ip_hdr ip_hdr;
	if (parse_ip_hdr(packet, header->caplen, &ip_hdr) == 0)
		printf("parsed ip hdr\n");
}

int main(int argc, char* argv[])
{
	char* dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	char filter_exp[] = "udp and udp[8:4] = 0xDEADBEEF";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (argc == 2) {
		dev = argv[1];
	} else if (argc > 2) {
		fprintf(stderr, "error: wrong options\n");
		exit(EXIT_FAILURE);
	} else {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Could not find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Could not get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("Device: %s\n", dev);
	printf("Filter: %s\n", filter_exp);

	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not Ethernet\n", dev);
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_freecode(&fp);
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, 0, got_packet, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
