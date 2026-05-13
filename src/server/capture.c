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
#include <server/capture.h>

#define SNAP_LEN 1518

void pcap_cap_free(cap_ctx_t* ctx)
{
	if (ctx->handle != NULL) {
		pcap_close(ctx->handle);
	}

	if (ctx->devices != NULL) {
		pcap_freealldevs(ctx->devices);
	}

	pcap_freecode(&ctx->fp);
}

int pcap_cap_init(cap_ctx_t* ctx, char* dev, const char* filter_exp)
{
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (dev == NULL) {
		if (pcap_findalldevs(&ctx->devices, ctx->errbuf) == -1) {
			fprintf(stderr, "pcap_findalldevs: %s\n", ctx->errbuf);
			return -1;
		}

		if (ctx->devices == NULL) {
			fprintf(stderr, "no devices found\n");
			return -1;
		}

		dev = ctx->devices->name;
	}

	if (pcap_lookupnet(dev, &net, &mask, ctx->errbuf) == -1) {
		net = 0;
		mask = 0;
	}

	ctx->handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, ctx->errbuf);
	if (ctx->handle == NULL) {
		fprintf(stderr, "pcap_open_live: %s\n", ctx->errbuf);
		pcap_cap_free(ctx);
		return -1;
	}

	if (pcap_datalink(ctx->handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not Ethernet\n", dev);
		pcap_cap_free(ctx);
		return -1;
	}

	if (pcap_compile(ctx->handle, &ctx->fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(ctx->handle));
		pcap_cap_free(ctx);
		return -1;
	}

	if (pcap_setfilter(ctx->handle, &ctx->fp) == -1) {
		fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(ctx->handle));
		pcap_cap_free(ctx);
		return -1;
	}

	return 0;
}
