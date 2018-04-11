
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "miner.h"
#include "sph/sph_jh.h"
#include "sph/sph_skein.h"
#include "sph/sph_blake.h"
#include "sph/sph_groestl.h"

#include "algorithm/cryptonight.h"
#include "algorithm/cn-aes-tbls.h"

#define VARIANT1_1(p) \
  do if (Variant > 0) { \
    const uint32_t tmp = (p); \
    static const uint32_t table = 0x75310; \
    const uint8_t index = ((tmp >> 26) & 12) | ((tmp >> 23) & 2); \
    (p) ^= ((table >> index) & 0x30) << 24; \
  } while(0)

#define VARIANT1_2(p) \
  do if (Variant > 0) { \
    (p) ^= tweak1_2; \
  } while(0)

#define VARIANT1_INIT() \
  if (Variant > 0 && Length < 43) { \
    quit(1, "Cryptonight variants need at least 43 bytes of data"); \
  } \
  const uint64_t tweak1_2 = Variant > 0 ? *(uint64_t*)(Input + 35) ^ CNCtx.State[24] : 0


static const uint64_t keccakf_rndc[24] = 
{
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint32_t keccakf_rotc[24] = 
{
    1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14, 
    27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

static const uint32_t keccakf_piln[24] = 
{
    10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4, 
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 
};

#define ROTL64(x, y)		(((x) << (y)) | ((x) >> (64 - (y))))
#define bitselect(a, b, c) 	((a) ^ ((c) & ((b) ^ (a))))

static void CNKeccakF1600(uint64_t *st)
{
	int i, round;
	uint64_t t, bc[5];

	for(round = 0; round < 24; ++round)
	{
		bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20] ^ ROTL64(st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22], 1UL);
		bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21] ^ ROTL64(st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23], 1UL);
		bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22] ^ ROTL64(st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24], 1UL);
		bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23] ^ ROTL64(st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20], 1UL);
		bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24] ^ ROTL64(st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21], 1UL);

		st[0] ^= bc[4];
		st[5] ^= bc[4];
		st[10] ^= bc[4];
		st[15] ^= bc[4];
		st[20] ^= bc[4];

		st[1] ^= bc[0];
		st[6] ^= bc[0];
		st[11] ^= bc[0];
		st[16] ^= bc[0];
		st[21] ^= bc[0];

		st[2] ^= bc[1];
		st[7] ^= bc[1];
		st[12] ^= bc[1];
		st[17] ^= bc[1];
		st[22] ^= bc[1];

		st[3] ^= bc[2];
		st[8] ^= bc[2];
		st[13] ^= bc[2];
		st[18] ^= bc[2];
		st[23] ^= bc[2];

		st[4] ^= bc[3];
		st[9] ^= bc[3];
		st[14] ^= bc[3];
		st[19] ^= bc[3];
		st[24] ^= bc[3];

		// Rho Pi
		t = st[1];
		for (i = 0; i < 24; ++i) {
			bc[0] = st[keccakf_piln[i]];
			st[keccakf_piln[i]] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		for(int i = 0; i < 25; i += 5)
		{
			uint64_t tmp1 = st[i], tmp2 = st[i + 1];

			st[i] = bitselect(st[i] ^ st[i + 2], st[i], st[i + 1]);
			st[i + 1] = bitselect(st[i + 1] ^ st[i + 3], st[i + 1], st[i + 2]);
			st[i + 2] = bitselect(st[i + 2] ^ st[i + 4], st[i + 2], st[i + 3]);
			st[i + 3] = bitselect(st[i + 3] ^ tmp1, st[i + 3], st[i + 4]);
			st[i + 4] = bitselect(st[i + 4] ^ tmp2, st[i + 4], tmp1);
		}

		//  Iota
		st[0] ^= keccakf_rndc[round];
	}
}

void CNKeccak(uint64_t *output, uint64_t *input, uint32_t Length)
{
	uint64_t st[25];
	
	// Copy 72 bytes
	//for(int i = 0; i < 9; ++i) st[i] = input[i];
	
	//st[9] = (input[9] & 0x00000000FFFFFFFFUL) | 0x0000000100000000UL;
	
	memcpy(st, input, Length);
	
	((uint8_t *)st)[Length] = 0x01;
	
	memset(((uint8_t *)st) + Length + 1, 0x00, 128 - Length - 1);
	
	for(int i = 16; i < 25; ++i) st[i] = 0x00UL;
	
	// Last bit of padding
	st[16] = 0x8000000000000000UL;
	
	CNKeccakF1600(st);
	
	memcpy(output, st, 200);
}

static inline uint64_t mul128(uint64_t a, uint64_t b, uint64_t* product_hi)
{
	uint64_t lo, hi;
	
	__asm__("mul %%rdx":
	"=a" (lo), "=d" (hi):
	"a" (a), "d" (b));
	
	*product_hi = hi;
	
	return lo;
}

#define BYTE(x, y)		(((x) >> ((y) << 3)) & 0xFF)
#define ROTL32(x, y)	(((x) << (y)) | ((x) >> (32 - (y))))

void CNAESRnd(uint32_t *X, const uint32_t *key)
{
	uint32_t Y[4];
	
	Y[0] = CNAESTbl[BYTE(X[0], 0)] ^ ROTL32(CNAESTbl[BYTE(X[1], 1)], 8) ^ ROTL32(CNAESTbl[BYTE(X[2], 2)], 16) ^ ROTL32(CNAESTbl[BYTE(X[3], 3)], 24);
	Y[1] = CNAESTbl[BYTE(X[1], 0)] ^ ROTL32(CNAESTbl[BYTE(X[2], 1)], 8) ^ ROTL32(CNAESTbl[BYTE(X[3], 2)], 16) ^ ROTL32(CNAESTbl[BYTE(X[0], 3)], 24);
	Y[2] = CNAESTbl[BYTE(X[2], 0)] ^ ROTL32(CNAESTbl[BYTE(X[3], 1)], 8) ^ ROTL32(CNAESTbl[BYTE(X[0], 2)], 16) ^ ROTL32(CNAESTbl[BYTE(X[1], 3)], 24);
	Y[3] = CNAESTbl[BYTE(X[3], 0)] ^ ROTL32(CNAESTbl[BYTE(X[0], 1)], 8) ^ ROTL32(CNAESTbl[BYTE(X[1], 2)], 16) ^ ROTL32(CNAESTbl[BYTE(X[2], 3)], 24);

	for(int i = 0; i < 4; ++i) X[i] = Y[i] ^ key[i];
}

void CNAESTransform(uint32_t *X, const uint32_t *Key)
{
	for(int i = 0; i < 10; ++i)
	{
		CNAESRnd(X, Key + (i << 2));
	}
}

#define SubWord(inw)		((CNAESSbox[BYTE(inw, 3)] << 24) | (CNAESSbox[BYTE(inw, 2)] << 16) | (CNAESSbox[BYTE(inw, 1)] << 8) | CNAESSbox[BYTE(inw, 0)])

void AESExpandKey256(uint32_t *keybuf)
{
	for(uint32_t c = 8, i = 1; c < 60; ++c)
	{
		// For 256-bit keys, an sbox permutation is done every other 4th uint generated, AND every 8th
		uint32_t t = ((!(c & 3))) ? SubWord(keybuf[c - 1]) : keybuf[c - 1];
		
		// If the uint we're generating has an index that is a multiple of 8, rotate and XOR with the round constant,
		// then XOR this with previously generated uint. If it's 4 after a multiple of 8, only the sbox permutation
		// is done, followed by the XOR. If neither are true, only the XOR with the previously generated uint is done.
		keybuf[c] = keybuf[c - 8] ^ ((!(c & 7)) ? ROTL32(t, 24U) ^ ((uint32_t)(CNAESRcon[i++])) : t);
	}
}

void cryptonight(uint8_t *Output, uint8_t *Input, uint32_t Length, int Variant)
{
	CryptonightCtx CNCtx;
	uint64_t text[16], a[2], b[2];
	uint32_t ExpandedKey1[64], ExpandedKey2[64];
	
	CNKeccak(CNCtx.State, Input, Length);

	VARIANT1_INIT();
	
	for(int i = 0; i < 4; ++i) ((uint64_t *)ExpandedKey1)[i] = CNCtx.State[i];
	for(int i = 0; i < 4; ++i) ((uint64_t *)ExpandedKey2)[i] = CNCtx.State[i + 4];
	
	AESExpandKey256(ExpandedKey1);
	AESExpandKey256(ExpandedKey2);
	
	memcpy(text, CNCtx.State + 8, 128);
	
	for(int i = 0; i < 0x4000; ++i)
	{
		for(int j = 0; j < 8; ++j)
		{
			CNAESTransform(text + (j << 1), ExpandedKey1);
		}
		
		memcpy(CNCtx.Scratchpad + (i << 4), text, 128);
	}
	
	a[0] = CNCtx.State[0] ^ CNCtx.State[4];
	b[0] = CNCtx.State[2] ^ CNCtx.State[6];
	a[1] = CNCtx.State[1] ^ CNCtx.State[5];
	b[1] = CNCtx.State[3] ^ CNCtx.State[7];
	
	for(int i = 0; i < 0x80000; ++i)
	{
		uint64_t c[2];
		memcpy(c, CNCtx.Scratchpad + ((a[0] & 0x1FFFF0) >> 3), 16);
		
		CNAESRnd(c, a);
		
		b[0] ^= c[0];
		b[1] ^= c[1];
		
		VARIANT1_1(b[1]);
		memcpy(CNCtx.Scratchpad + ((a[0] & 0x1FFFF0) >> 3), b, 16);
		
		memcpy(b, CNCtx.Scratchpad + ((c[0] & 0x1FFFF0) >> 3), 16);
		
		uint64_t hi;
		
		a[1] += mul128(c[0], b[0], &hi);
		a[0] += hi;
		
		VARIANT1_2(a[1]);
		memcpy(CNCtx.Scratchpad + ((c[0] & 0x1FFFF0) >> 3), a, 16);
		VARIANT1_2(a[1]);
		
		a[0] ^= b[0];
		a[1] ^= b[1];
		
		b[0] = c[0];
		b[1] = c[1];
	}
	
	memcpy(text, CNCtx.State + 8, 128);
	
	for(int i = 0; i < 0x4000; ++i)
	{
		for(int j = 0; j < 16; ++j) text[j] ^= CNCtx.Scratchpad[(i << 4) + j];
		
		for(int j = 0; j < 8; ++j)
		{
			CNAESTransform(text + (j << 1), ExpandedKey2);
		}
	}
	
	// Tail Keccak and arbitrary hash func here
	memcpy(CNCtx.State + 8, text, 128);
	
	CNKeccakF1600(((uint64_t *)CNCtx.State));
	
	switch(CNCtx.State[0] & 3)
	{
		case 0:
		{
			sph_blake256_context blakectx;
			sph_blake256_init(&blakectx);
			sph_blake256(&blakectx, CNCtx.State, 200);
			sph_blake256_close(&blakectx, Output);
			break;
		}
		case 1:
		{
			sph_groestl256_context groestl256;
			sph_groestl256_init(&groestl256);
			sph_groestl256(&groestl256, CNCtx.State, 200);
			sph_groestl256_close(&groestl256, Output);
			break;
		}
		case 2:
		{
			sph_jh256_context jh256;
			sph_jh256_init(&jh256);
			sph_jh256(&jh256, CNCtx.State, 200);
			sph_jh256_close(&jh256, Output);
			break;
		}
		case 3:
		{
			sph_skein256_context skein256;
			sph_skein256_init(&skein256);
			sph_skein256(&skein256, CNCtx.State, 200);
			sph_skein256_close(&skein256, Output);
			break;
		}
	}
}

void cryptonight_regenhash(struct work *work)
{
	uint32_t data[20];
	int variant = cryptonight_variant(work);
	uint32_t *ohash = (uint32_t *)(work->hash);
	
	memcpy(data, work->data, work->XMRBlobLen);
		
	cryptonight(ohash, data, work->XMRBlobLen, variant);
	
	char *tmpdbg = bin2hex((uint8_t*) ohash, 32);
	
	applog(LOG_DEBUG, "cryptonight_regenhash (variant %d): %s", variant, tmpdbg);
	
	free(tmpdbg);
	
	//memset(ohash, 0x00, 32);
}
