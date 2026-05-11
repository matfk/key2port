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
#include <core/string.h>
#include <core/types.h>

#define SNAP_LEN 1518

static char errbuf[PCAP_ERRBUF_SIZE];
static pcap_t* handle = NULL;
static pcap_if_t* devices = NULL;

static struct bpf_program fp;
static int filter_init = 0;

void pcap_cap_free()
{
	if (filter_init) {
		pcap_freecode(&fp);
	}

	if (handle != NULL) {
		pcap_close(handle);
	}

	if (devices != NULL) {
		pcap_freealldevs(devices);
	}
}

int pcap_cap_init(char* dev, const char* filter_exp)
{
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (dev == NULL) {
		if (pcap_findalldevs(&devices, errbuf) == -1) {
			fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
			return -1;
		}

		if (devices == NULL) {
			fprintf(stderr, "no devices found\n");
			return -1;
		}

		dev = devices->name;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", errbuf);
		pcap_cap_free();
		return -1;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not Ethernet\n", dev);
		pcap_cap_free();
		return -1;
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
		pcap_cap_free();
		return -1;
	}

	filter_init = 1;

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
		pcap_cap_free();
		return -1;
	}

	return 0;
}

void pcap_cap_start(pcap_handler capture_handler)
{
	pcap_loop(handle, 0, capture_handler, NULL);
}
