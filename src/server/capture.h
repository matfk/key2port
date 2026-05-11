#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

int pcap_cap_init(char* dev, const char* filter_exp);
pcap_t* pcap_get_handle();
void pcap_cap_free();

#endif
