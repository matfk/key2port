#ifndef KEY_H
#define KEY_H

#include <core/types.h>

u8* b64_decode_alloc(const char* b64, size_t* outlen);
int parse_ssh_ed25519_publine(const char* line, u8 out_pub[32]);
int parse_openssh_priv_pem(const char* pem, u8 out_seed[32]);

#endif
