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
#include <server/packet_parser.h>

int ethernet_parse_hdr(const u8* packet, size_t len, struct ethernet_hdr* hdr)
{
	if (len < ETHER_LEN)
		return 1;

	memcpy(hdr, packet, ETHER_LEN);
	hdr->ether_type = ntohs(hdr->ether_type);

	if (hdr->ether_type != 0x0800)
		return 1;

	return 0;
}

int ip_parse_hdr(const u8* packet, size_t len, struct ip_hdr* hdr, int* out_ip_len)
{
	if (len < IP_LEN)
		return 1;

	memcpy(hdr, packet, IP_LEN);
	if (IP_V(hdr) != 4)
		return 1;

	size_t size_ip = IP_HL(hdr) * 4;
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

int udp_parse_hdr(const u8* packet, size_t len, struct udp_hdr* hdr)
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

int parse_hdrs(const u8* packet, size_t packet_len, struct ethernet_hdr* eth, struct ip_hdr* ip, struct udp_hdr* udp)
{
	u8* p = (u8*)packet;
	int ip_len;

	if (ethernet_parse_hdr(p, packet_len, eth) != 0)
		return -1;

	p += ETHER_LEN;
	packet_len -= ETHER_LEN;

	if (ip_parse_hdr(p, packet_len, ip, &ip_len) != 0)
		return -1;

	p += ip_len;
	packet_len -= ip_len;

	if (udp_parse_hdr(p, packet_len, udp) != 0)
		return -1;

	p += UDP_LEN;

	return (int)(p - packet);
}
