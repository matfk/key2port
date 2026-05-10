#ifndef WORKER_H
#define WORKER_H

#include <core/types.h>
#include <pcap/pcap.h>

#define WORKER_NUM 16

void worker_pool_init();
void worker_pool_join();
void* worker(void* arg);
void got_packet(u8* args, const struct pcap_pkthdr* header, const u8* packet);

#endif
