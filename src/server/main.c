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
#include <server/capture.h>
#include <core/cpu.h>

int main(int argc, char* argv[])
{
	int nprocs = getnprocs();
	char filter_exp[] = "udp and udp[8:4] = 0x53504100";
	char* dev = argv[1];

	if (nft_ctx_init() != 0) {
		return 1;
	}

	if (pcap_cap_init(dev, filter_exp) != 0) {
		return 1;
	}

	worker_pool_init(nprocs);
	pcap_cap_start(worker_dispatch);

	pcap_cap_free();
	worker_pool_join();
	nft_free();
	return 0;
}
