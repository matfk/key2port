#ifndef NFT_H
#define NFT_H

#include <core/types.h>
#include <nftables/libnftables.h>

#define NFT_TABLE "key2port"
#define NFT_MAX_TTL 3600

int nft_ctx_init();
struct nft_ctx* nft_ctx_get();
void nft_free();
int nft_allow_port(u16 port, const char* ip, u32 ttl);

#endif
