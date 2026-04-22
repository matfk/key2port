#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("usage: [payload]\n");
		return 1;
	}

	FILE* file = fopen("spa.bin", "wb");
	if (file == NULL) {
		perror("failed to open spa.bin");
		return 1;
	}

	uint32_t magic = htonl(0x53504100);
	uint16_t flags = htons(0x0000);
	uint32_t client_id = htonl(12345);
	uint32_t timestamp = htonl((uint32_t)time(NULL));
	u_char nonce[12] = { 0 };

	uint32_t length = (uint32_t)strlen(argv[1]);
	uint32_t netlength = htonl(length);

	FILE* rand = fopen("/dev/urandom", "rb");
	if (rand != NULL) {
		fread(nonce, sizeof(u_char), 12, rand);
		fclose(rand);
	}

	fwrite(&magic, sizeof(magic), 1, file);
	fwrite(&flags, sizeof(flags), 1, file);
	fwrite(&client_id, sizeof(client_id), 1, file);
	fwrite(&timestamp, sizeof(timestamp), 1, file);
	fwrite(nonce, 1, sizeof(nonce), file);
	fwrite(&netlength, sizeof(netlength), 1, file);
	fwrite(argv[1], sizeof(u_char), length, file);

	fclose(file);
	return 0;
}
