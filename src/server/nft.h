#ifndef NFT_H
#define NFT_H

#include <core/types.h>
#include <nftables/libnftables.h>

#define NFT_TABLE "occultus"
#define NFT_MAX_TTL 3600

int nft_ctx_init();
struct nft_ctx* nft_get_ctx();
void nft_free();
int nft_add_ipv4(char* ipv4, u16 port, u32 ttl);

#endif
