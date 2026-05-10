#ifndef SPSC_H
#define SPSC_H

#include <core/types.h>
#include <stdalign.h>

#define SPSC_CAPACITY 1024
#define CACHE_LINE 64

#define STATE_AWAKE 0
#define STATE_SLEEP 1

struct spsc_ring {
	void* buf[SPSC_CAPACITY];
	alignas(CACHE_LINE) atomic_size_t head;
	alignas(CACHE_LINE) atomic_size_t tail;
	atomic_int consumer_state;
};

void spsc_init(struct spsc_ring* ring);
int spsc_push(struct spsc_ring* ring, void* data);
void* spsc_pop(struct spsc_ring* ring);

#endif
