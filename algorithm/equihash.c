#include <stdint.h>

#include "config.h"
#include "miner.h"
#include "algorithm/equihash.h"

#include "algorithm.h"

#define N   200UL
#define K   9UL

#define COLLISION_BIT_LENGTH            (N / (K + 1))
#define COLLISION_BYTE_LENGTH           ((COLLISION_BIT_LENGTH + 7) / 8)
#define INIT_SIZE                       (1 << (COLLISION_BIT_LENGTH + 1))
#define HASH_LENGTH                     ((K + 1) * COLLISION_BYTE_LENGTH)
#define INDICES_PER_HASH_OUTPUT         (512 / N)
#define HASH_OUTPUT                     (INDICES_PER_HASH_OUTPUT * N/8)

#define rotr64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))


static const uint8_t blake2b_sigma[12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

    
static const uint64_t blake2b_IV[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint64_t blake2b_h[8] = {
  0x6a09e667f2bdc93aULL, 0xbb67ae8584caa73bULL, 
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 
  0x48ec89c38820de31ULL, 0x5be0cd10137e21b1ULL
};


// block_header_size: 108 byte
// nonce_size: 32 byte
// birthday_size: 4 byte
// nonce in high part of m[1]


#define G(r,i,a,b,c,d) \
  a = a + b + m[blake2b_sigma[r][2*i]]; \
  d = rotr64(d ^ a, 32); \
  c = c + d; \
  b = rotr64(b ^ c, 24); \
  a = a + b + m[blake2b_sigma[r][2*i+1]]; \
  d = rotr64(d ^ a, 16); \
  c = c + d; \
  b = rotr64(b ^ c, 63);

#define ROUND(r)                  \
  G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
  G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
  G(r,2,v[ 2],v[ 6],v[10],v[14]); \
  G(r,3,v[ 3],v[ 7],v[11],v[15]); \
  G(r,4,v[ 0],v[ 5],v[10],v[15]); \
  G(r,5,v[ 1],v[ 6],v[11],v[12]); \
  G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
  G(r,7,v[ 3],v[ 4],v[ 9],v[14]);
  
  
#define G_fast(r,i,a,b,c,d) \
  a = a + b + (blake2b_sigma[r][2*i] == 1 ? m1 : 0); \
  d = rotr64(d ^ a, 32); \
  c = c + d; \
  b = rotr64(b ^ c, 24); \
  a = a + b + (blake2b_sigma[r][2*i+1] == 1 ? m1 : 0); \
  d = rotr64(d ^ a, 16); \
  c = c + d; \
  b = rotr64(b ^ c, 63);

#define ROUND_fast(r)                  \
  G_fast(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
  G_fast(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
  G_fast(r,2,v[ 2],v[ 6],v[10],v[14]); \
  G_fast(r,3,v[ 3],v[ 7],v[11],v[15]); \
  G_fast(r,4,v[ 0],v[ 5],v[10],v[15]); \
  G_fast(r,5,v[ 1],v[ 6],v[11],v[12]); \
  G_fast(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
  G_fast(r,7,v[ 3],v[ 4],v[ 9],v[14]);


void equihash_calc_mid_hash(uint64_t mid_hash[8], uint8_t* header) {
  uint64_t v[16], *m = (uint64_t*) header;
  for (int i = 0; i < 8; i++) {
    v[i] = blake2b_h[i];
    v[i+8] = blake2b_IV[i];
  }
  v[12] ^= 128;
  for (int r = 0; r < 12; r++) {
    ROUND(r)
  }
  for (int i = 0; i < 8; i++) 
    mid_hash[i] = blake2b_h[i] ^ v[i] ^ v[i+8];
}

void blake2b_hash(uint8_t *hash, uint64_t mid_hash[8], uint32_t bday) {
  uint64_t v[16], tmp[8];
  uint64_t m1 = (uint64_t) bday << 32;
  for (int i = 0; i < 8; i++) {
    v[i] = mid_hash[i];
    v[i+8] = blake2b_IV[i];
  }
  v[12] ^= 140 + sizeof(bday);
  v[14] ^= (int64_t) -1;
  for (int r = 0; r < 12; r++) {
    ROUND_fast(r)
  }
  for (int i = 0; i < 8; i++) 
    tmp[i] = mid_hash[i] ^ v[i] ^ v[i+8];
  memcpy(hash, tmp, 50);
}

void equihash_calc_hash(uint8_t hash[25], uint64_t mid_hash[8], uint32_t bday) {
  uint8_t tmp[50];
  blake2b_hash(tmp, mid_hash, bday/2);
  memcpy(hash, tmp + (bday & 1 ? 25 : 0), 25);
}


// These two copied from the ref impl, for now.
void ExpandArray(const unsigned char* in, size_t in_len,
                 unsigned char* out, size_t out_len,
                 size_t bit_len)
{
  size_t byte_pad = 0;
  size_t out_width = ((bit_len+7)/8 + byte_pad);
  uint32_t bit_len_mask = (((uint32_t)1 << bit_len) - 1);

  // The acc_bits least-significant bits of acc_value represent a bit sequence
  // in big-endian order.
  size_t acc_bits = 0;
  uint32_t acc_value = 0;

  size_t j = 0;
  for (size_t i = 0; i < in_len; i++) {
    acc_value = (acc_value << 8) | in[i];
    acc_bits += 8;

    // When we have bit_len or more bits in the accumulator, write the next
    // output element.
    if (acc_bits >= bit_len) {
      acc_bits -= bit_len;
      for (size_t x = 0; x < byte_pad; x++) {
        out[j+x] = 0;
      }
      for (size_t x = byte_pad; x < out_width; x++) {
        out[j+x] = (
          // Big-endian
          acc_value >> (acc_bits+(8*(out_width-x-1)))
        ) & (
          // Apply bit_len_mask across byte boundaries
          (bit_len_mask >> (8*(out_width-x-1))) & 0xFF
        );
      }
      j += out_width;
    }
  }
}


void CompressArray(const unsigned char* in, size_t in_len,
                   unsigned char* out, size_t out_len,
                   size_t bit_len, size_t byte_pad)
{
  size_t in_width = ((bit_len+7)/8 + byte_pad);
  uint32_t bit_len_mask = (((uint32_t)1 << bit_len) - 1);

  // The acc_bits least-significant bits of acc_value represent a bit sequence
  // in big-endian order.
  size_t acc_bits = 0;
  uint32_t acc_value = 0;

  size_t j = 0;
  for (size_t i = 0; i < out_len; i++) {
    // When we have fewer than 8 bits left in the accumulator, read the next
    // input element.
    if (acc_bits < 8) {
      acc_value = acc_value << bit_len;
      for (size_t x = byte_pad; x < in_width; x++) {
        acc_value = acc_value | (
          (
            // Apply bit_len_mask across byte boundaries
            in[j+x] & ((bit_len_mask >> (8*(in_width-x-1))) & 0xFF)
          ) << (8*(in_width-x-1))
        ); // Big-endian
      }
      j += in_width;
      acc_bits += bit_len;
    }

    acc_bits -= 8;
    out[i] = (acc_value >> acc_bits) & 0xFF;
  }
}


static inline void sort_pair(uint32_t *a, uint32_t len)
{
  uint32_t    *b = a + len;
  uint32_t     tmp, need_sorting = 0;
  for (uint32_t i = 0; i < len; i++) {
    if (need_sorting || a[i] > b[i]) {
      need_sorting = 1;
      tmp = a[i];
      a[i] = b[i];
      b[i] = tmp;
    }
    else if (a[i] < b[i])
      break;
  }
}


bool submit_tested_work(struct thr_info *, struct work *);

uint32_t equihash_verify_sol(struct work *work, sols_t *sols, int sol_i)
{
  uint32_t thr_id = work->thr->id;
  uint32_t	*inputs = sols->values[sol_i];
  uint32_t	seen_len = (1 << (PREFIX + 1)) / 8;
  uint8_t	seen[seen_len];
  uint32_t	i;
  uint8_t	tmp;
  // look for duplicate inputs
  memset(seen, 0, seen_len);
  for (i = 0; i < (1 << PARAM_K); i++) {
    
    if (inputs[i] / 8 >= seen_len) {
      sols->valid[sol_i] = 0;
      return 0;
    }
    tmp = seen[inputs[i] / 8];
    seen[inputs[i] / 8] |= 1 << (inputs[i] & 7);
    if (tmp == seen[inputs[i] / 8]) {
      // at least one input value is a duplicate
      sols->valid[sol_i] = 0;
      return 0;
    }
  }
  // the valid flag is already set by the GPU, but set it again because
  // I plan to change the GPU code to not set it
  sols->valid[sol_i] = 1;
  // sort the pairs in place
  for (uint32_t level = 0; level < PARAM_K; level++) {
    for (i = 0; i < (1 << PARAM_K); i += (2 << level)) {
      sort_pair(&inputs[i], 1 << level);
    }
  }
    
  for (i = 0; i < (1 << PARAM_K); i++)
    inputs[i] = htobe32(inputs[i]);
    
  CompressArray((unsigned char*) inputs, 512*4, work->equihash_data + 143, 1344, 21, 1);
  
  gen_hash(work->equihash_data, 1344 + 143, work->hash); 
  
  if (*(uint64_t*) (work->hash + 24) < *(uint64_t*) (work->target + 24)) {
    submit_tested_work(work->thr, work);
  }
  return 1;
}

void equihash_regenhash(struct work *work)
{

}

