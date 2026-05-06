#include <nftables/libnftables.h>
#include <string.h>
#include <stdlib.h>
#include <core/types.h>
#include "nft.h"

static struct nft_ctx* nft = NULL;

int nft_ctx_init()
{
	if (nft)
		return 0;

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft == NULL) {
		fprintf(stderr, "nftables: failed to initialize context\n");
		return -1;
	}

	return 0;
}

struct nft_ctx* nft_get_ctx()
{
	return nft;
}

void nft_free()
{
	if (nft) {
		nft_ctx_free(nft);
		nft = NULL;
	}
}

int nft_add_ipv4(char* ipv4, u16 port, u32 ttl)
{
	if (nft == NULL) {
		fprintf(stderr, "nftables: context not initialized\n");
		return -1;
	}

	char commands[1024];
	snprintf(commands, sizeof(commands),
		 "add table inet occultus\n"
		 "add set inet occultus temp_allowed { type ipv4_addr . inet_service; flags timeout; }\n"
		 "add chain inet occultus prerouting { type filter hook prerouting priority -100; }\n"

		 // flush chain to prevent duplicate rules
		 "flush chain inet occultus prerouting\n"

		 // mark with 0x99
		 "add rule inet occultus prerouting ip saddr . tcp dport @temp_allowed meta mark set 0x99\n"

		 "add element inet %s temp_allowed { %s . %d timeout %ds }\n",
		 NFT_TABLE, ipv4, port, ttl);

	if (nft_run_cmd_from_buffer(nft, commands) < 0) {
		fprintf(stderr, "nftables: failed to apply rule [ipv4=%s port=%d ttl=%d]\n", ipv4, port, ttl);
		return -1;
	}

	return 0;
}
