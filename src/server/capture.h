#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap/pcap.h>

int pcap_cap_init(char* dev, const char* filter_exp);
void pcap_cap_start(pcap_handler capture_handler);
void pcap_cap_free();

#endif
