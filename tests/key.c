#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "types.h"

static uint32_t be32(const u8* b)
{
	return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

static u8* b64_decode_alloc(const char* b64, size_t* outlen)
{
	size_t inlen = strlen(b64);
	size_t max_out = (inlen * 3) / 4 + 8;
	u8* out = malloc(max_out);
	if (!out)
		return NULL;
	if (sodium_base642bin(out, max_out, b64, inlen, NULL, outlen, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
		free(out);
		return NULL;
	}
	return out;
}

int parse_ssh_ed25519_publine(const char* line, u8 out_pub[32])
{
	const char* p = strchr(line, ' ');
	if (!p)
		return -1;
	while (*p == ' ')
		p++;
	const char* q = strchr(p, ' ');
	size_t b64len = q ? (size_t)(q - p) : strlen(p);
	char* b64 = strndup(p, b64len);
	if (!b64)
		return -1;

	size_t bloblen;
	u8* blob = b64_decode_alloc(b64, &bloblen);
	free(b64);
	if (!blob)
		return -1;

	if (bloblen < 4) {
		free(blob);
		return -1;
	}
	uint32_t alglen = be32(blob);
	if (4 + alglen + 4 + 32 > bloblen) {
		free(blob);
		return -1;
	}
	if (alglen != strlen("ssh-ed25519") || memcmp(blob + 4, "ssh-ed25519", alglen) != 0) {
		free(blob);
		return -1;
	}

	uint32_t off = 4 + alglen;
	uint32_t pklen = be32(blob + off);
	if (pklen != 32) {
		free(blob);
		return -1;
	}
	memcpy(out_pub, blob + off + 4, 32);
	sodium_memzero(blob, bloblen);
	free(blob);
	return 0;
}

int parse_openssh_priv_pem(const char* pem, u8 out_seed[32])
{
	const char* begin = strstr(pem, "-----BEGIN OPENSSH PRIVATE KEY-----");
	const char* end = strstr(pem, "-----END OPENSSH PRIVATE KEY-----");
	if (!begin || !end || end <= begin)
		return -1;
	const char* body = begin;
	body = strchr(body, '\n');
	if (!body)
		return -1;
	body++;
	size_t b64cap = (size_t)(end - body) + 1;
	char* b64 = malloc(b64cap);
	if (!b64)
		return -1;
	size_t idx = 0;
	const char* line = body;
	while (line < end) {
		const char* nl = strchr(line, '\n');
		size_t len = nl ? (size_t)(nl - line) : (size_t)(end - line);
		if (len > 0) {
			memcpy(b64 + idx, line, len);
			idx += len;
		}
		if (!nl)
			break;
		line = nl + 1;
	}
	b64[idx] = '\0';

	size_t binlen;
	u8* bin = b64_decode_alloc(b64, &binlen);
	free(b64);
	if (!bin)
		return -1;

	// verify magic "openssh-key-v1\0"
	const char magic[] = "openssh-key-v1\0";
	size_t off = 0;
	if (binlen < sizeof(magic) - 1 || memcmp(bin, magic, sizeof(magic) - 1) != 0) {
		free(bin);
		return -1;
	}
	off += sizeof(magic) - 1;

	// read ciphername
	if (off + 4 > binlen) {
		free(bin);
		return -1;
	}
	uint32_t len = be32(bin + off);
	off += 4;
	if (off + len > binlen) {
		free(bin);
		return -1;
	}
	char* ciphername = strndup((char*)(bin + off), len);
	off += len;

	// read kdfname
	if (off + 4 > binlen) {
		free(ciphername);
		free(bin);
		return -1;
	}
	len = be32(bin + off);
	off += 4;
	if (off + len > binlen) {
		free(ciphername);
		free(bin);
		return -1;
	}
	char* kdfname = strndup((char*)(bin + off), len);
	off += len;

	// read kdfoptions
	if (off + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	len = be32(bin + off);
	off += 4;
	if (off + len > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	off += len;

	// read nkeys
	if (off + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	uint32_t nkeys = be32(bin + off);
	off += 4;
	if (nkeys < 1) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}

	// read pubkeyblob
	for (uint32_t i = 0; i < nkeys; i++) {
		if (off + 4 > binlen) {
			free(ciphername);
			free(kdfname);
			free(bin);
			return -1;
		}
		uint32_t plen = be32(bin + off);
		off += 4;
		if (off + plen > binlen) {
			free(ciphername);
			free(kdfname);
			free(bin);
			return -1;
		}
		off += plen;
	}

	// read privblob length
	if (off + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	uint32_t privlen = be32(bin + off);
	off += 4;
	if (off + privlen > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}

	// only support unencrypted
	if (strcmp(kdfname, "none") != 0 || strcmp(ciphername, "none") != 0) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -2;
	}

	// parse checkints then key entries
	size_t p = off;
	if (p + 4 + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	uint32_t check1 = be32(bin + p);
	p += 4;
	uint32_t check2 = be32(bin + p);
	p += 4;

	// parse first key entry
	if (p + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	uint32_t alglen = be32(bin + p);
	p += 4;
	if (p + alglen > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	if (alglen != strlen("ssh-ed25519") || memcmp(bin + p, "ssh-ed25519", alglen) != 0) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	p += alglen;

	// pubkey blob
	if (p + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	uint32_t publen = be32(bin + p);
	p += 4;
	if (p + publen > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	p += publen;

	// privkey blob (string)
	if (p + 4 > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}
	uint32_t privkeylen = be32(bin + p);
	p += 4;
	if (p + privkeylen > binlen) {
		free(ciphername);
		free(kdfname);
		free(bin);
		return -1;
	}

	size_t subp = p;
	if (privkeylen >= 4) {
		uint32_t inner_len = be32(bin + subp);
		subp += 4;
		if (subp + inner_len <= p + privkeylen && inner_len >= 32) {
			// inner contains seed || pub
			memcpy(out_seed, bin + subp, 32);
			free(ciphername);
			free(kdfname);
			sodium_memzero(bin, binlen);
			free(bin);
			return 0;
		}
	}
	// fallback: if privkeylen >=32, take first 32 bytes
	if (privkeylen >= 32) {
		memcpy(out_seed, bin + p, 32);
		free(ciphername);
		free(kdfname);
		sodium_memzero(bin, binlen);
		free(bin);
		return 0;
	}

	free(ciphername);
	free(kdfname);
	sodium_memzero(bin, binlen);
	free(bin);
	return -1;
}

u8* read_key_file(const char* path, u32* outlen)
{
	FILE* file = fopen(path, "r");
	if (file == NULL) {
		perror("fopen");
		return NULL;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		perror("fseek");
		return NULL;
	}

	long int file_size = ftell(file);
	printf("FileSize: %ld\n", file_size);
}

int main(void)
{
	if (sodium_init() < 0)
		return 1;

	read_key_file("sk", NULL);

	const char* publine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGh6QF4mCoOJUQk9Qz80SzCn/JJahViojlIo4pDghW59 elijah@homestead";
	u8 pub[32];
	if (parse_ssh_ed25519_publine(publine, pub) == 0) {
		printf("Parsed public key (first 4 bytes): %02x %02x %02x %02x\n", pub[0], pub[1], pub[2], pub[3]);
	} else {
		printf("Failed to parse public line\n");
	}

	const char* pem =
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBoekBeJgqDiVEJPUM/NEswp/ySWoVYqI5SKOKQ4IVufQAAAJitjRw/rY0c\nPwAAAAtzc2gtZWQyNTUxOQAAACBoekBeJgqDiVEJPUM/NEswp/ySWoVYqI5SKOKQ4IVufQ\nAAAEDyVSZ73CddrxlQRX3X9HQEI4LxNwKDK1ougiUbTi727mh6QF4mCoOJUQk9Qz80SzCn\n/JJahViojlIo4pDghW59AAAAEGVsaWphaEBob21lc3RlYWQBAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----";
	u8 seed[32];
	int r = parse_openssh_priv_pem(pem, seed);
	if (r == 0) {
		u8 pk[32], sk[64];
		crypto_sign_ed25519_seed_keypair(pk, sk, seed);
		printf("Derived public key (first 4 bytes): %02x %02x %02x %02x\n", pk[0], pk[1], pk[2], pk[3]);
		sodium_memzero(sk, sizeof(sk));
		sodium_memzero(seed, sizeof(seed));
	} else if (r == -2) {
		printf("Encrypted private key - not supported by this example\n");
	} else {
		printf("Failed to parse private key\n");
	}

	return 0;
}
