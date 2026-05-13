#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

typedef struct {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	pcap_if_t* devices;
	struct bpf_program fp;
} cap_ctx_t;

void pcap_cap_free(cap_ctx_t* ctx);
int pcap_cap_init(cap_ctx_t* ctx, char* dev, const char* filter_exp);

#endif
