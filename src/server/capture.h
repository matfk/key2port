#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

typedef struct {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	pcap_if_t* devices;
	struct bpf_program fp;
} cap_ctx;

void cap_ctx_free(cap_ctx* ctx);
pcap_t* cap_ctx_get_handle(cap_ctx* ctx);
int cap_ctx_init(cap_ctx* ctx, char* dev, const char* filter_exp);

#endif
