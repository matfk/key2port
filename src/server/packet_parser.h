#ifndef PACKET_PARSER
#define PACKET_PARSER

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

#define SNAP_LEN 1518
#define ETHER_LEN 14
#define ETHER_ADDR_LEN 6
#define IP_LEN 20
#define BUFFER_LEN 256
#define UDP_LEN 8

struct ethernet_hdr {
	u8 ether_dhost[ETHER_ADDR_LEN];
	u8 ether_shost[ETHER_ADDR_LEN];
	u16 ether_type;
} __attribute__((packed));

struct ip_hdr {
	u8 ip_vhl;
	u8 ip_tos;
	u16 ip_len;
	u16 ip_id;
	u16 ip_off;
	u8 ip_ttl;
	u8 ip_p;
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

int ethernet_parse_hdr(const u8* packet, size_t len, struct ethernet_hdr* hdr);
int ip_parse_hdr(const u8* packet, size_t len, struct ip_hdr* hdr, int* out_ip_len);
int udp_parse_hdr(const u8* packet, size_t len, struct udp_hdr* hdr);
int parse_hdrs(const u8* packet, size_t packet_len, struct ethernet_hdr* eth, struct ip_hdr* ip, struct udp_hdr* udp);

#endif
