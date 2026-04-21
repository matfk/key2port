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

static atomic_int count = 0;

static void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
	int curr_count = atomic_fetch_add_explicit(&count, 1, memory_order_relaxed);
	printf("got packet: %d\n", curr_count);
}

int main(void)
{
	char* dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	char filter_exp[] = "port 22";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Could not find default device: %s\n", errbuf);
		exit(EXIT_FAILURE);
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
