#include <core/types.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include "spsc.h"

static inline void futex_wait(atomic_int* p, int expected)
{
	syscall(SYS_futex, p, FUTEX_WAIT_PRIVATE, expected, NULL, NULL, 0);
}

static inline void futex_wake_one(atomic_int* p)
{
	syscall(SYS_futex, p, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

struct spsc_ring spsc_init()
{
	struct spsc_ring ring;
	atomic_store(&ring.head, 0);
	atomic_store(&ring.tail, 0);
	return ring;
}

int spsc_push(struct spsc_ring* ring, void* data)
{
	size_t head = atomic_load_explicit(&ring->head, memory_order_acquire);
	size_t tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);

	size_t next_tail = (tail + 1) % SPSC_CAPACITY;
	if (head == next_tail)
		return -1;

	ring->buf[tail] = data;
	atomic_store_explicit(&ring->tail, next_tail, memory_order_release);
	atomic_thread_fence(memory_order_seq_cst);

	if (atomic_load_explicit(&ring->consumer_state, memory_order_seq_cst) == STATE_SLEEP) {
		atomic_store_explicit(&ring->consumer_state, STATE_AWAKE, memory_order_relaxed);
		futex_wake_one(&ring->consumer_state);
	}

	return 0;
}

void* spsc_pop(struct spsc_ring* ring)
{
	while (1) {
		size_t head = atomic_load_explicit(&ring->head, memory_order_relaxed);
		size_t tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

		// has data: returns it
		if (head != tail) {
			size_t new_head = (head + 1) % SPSC_CAPACITY;
			void* data = ring->buf[head];

			atomic_store_explicit(&ring->head, new_head, memory_order_release);
			return data;
		}

		// is empty: goes to sleep
		atomic_store_explicit(&ring->consumer_state, STATE_SLEEP, memory_order_seq_cst);
		atomic_thread_fence(memory_order_seq_cst);
		tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

		if (head != tail) {
			atomic_store_explicit(&ring->consumer_state, STATE_AWAKE, memory_order_relaxed);
			continue;
		}

		futex_wait(&ring->consumer_state, STATE_SLEEP);
		atomic_store_explicit(&ring->consumer_state, STATE_AWAKE, memory_order_relaxed);
	}
}
