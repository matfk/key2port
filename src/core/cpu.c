#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

size_t getnprocs()
{
	size_t nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	if (nprocs < 1) {
		perror("sysconf");
		return 0;
	}

	return nprocs;
}
