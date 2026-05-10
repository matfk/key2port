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
#include <core/cpu.h>

int start_capture(char* dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	char filter_exp[] = "udp and udp[8:4] = 0x53504100";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_if_t* devices = NULL;

	if (dev == NULL) {
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
		pcap_freealldevs(devices);
		exit(EXIT_FAILURE);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not Ethernet\n", dev);
		pcap_freealldevs(devices);
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
		pcap_freealldevs(devices);
		pcap_close(handle);
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
		pcap_freecode(&fp);
		pcap_close(handle);
		pcap_freealldevs(devices);
		exit(EXIT_FAILURE);
	}

	if (nft_ctx_init() != 0) {
		pcap_freecode(&fp);
		pcap_close(handle);
		pcap_freealldevs(devices);
		nft_free();
		exit(EXIT_FAILURE);
	}

	worker_pool_init(nprocs());
	pcap_loop(handle, 0, worker_dispatch, NULL);
	worker_pool_join();

	pcap_freecode(&fp);
	pcap_close(handle);
	pcap_freealldevs(devices);
	nft_free();
	return 0;
}

int main(int argc, char* argv[])
{
	start_capture(argv[1]);
	return 0;
}
