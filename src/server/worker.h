#ifndef WORKER_H
#define WORKER_H

#include <core/types.h>
#include <pcap/pcap.h>
#include <stdlib.h>

void* worker(void* arg);
void worker_dispatch(u8* args, const struct pcap_pkthdr* header, const u8* packet);
void worker_pool_init(size_t n);
void worker_pool_join();

#endif
