#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "miner.h"
#include "sph/sph_sha2.h"


static const int8_t base58_lookup[] =
{
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
  -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
  22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
  -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
  47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

/*
 * Utility function to decode base58 wallet address
 * out should have at least 1/2 the size of base58_input
 * input_size must not exceed 200
 */
static bool base58_decode(uint8_t* out, int* out_size, char* base58_input, int input_size)
{
  if (input_size == 0)
    return false;
  if (input_size > 200)
    return false;
  uint32_t base_array[32] = {0};
  uint32_t base_track[32] = {0};
  int base_array_size = 1;
  base_array[0] = 0;
  base_track[0] = 57;
  // calculate exact size of output
  for (int i = 0; i < input_size-1; i++)
  {
    // multiply baseTrack with 58
    for (int b = base_array_size-1; b >= 0; b--)
    {
      uint64_t mwc = (uint64_t) base_track[b] * 58ULL;
      base_track[b] = (uint32_t) (mwc & 0xFFFFFFFFUL);
      mwc >>= 32;
      if (mwc != 0)
      {
        // add carry
        for (int carry_idx = b + 1; carry_idx < base_array_size; carry_idx++)
        {
          mwc += (uint64_t) base_track[carry_idx];
          base_track[carry_idx] = (uint32_t) (mwc & 0xFFFFFFFFUL);
          mwc >>= 32;
          if (mwc == 0)
            break;
        }
        if (mwc)
        {
          // extend
          base_track[base_array_size] = (uint32_t) mwc;
          base_array_size++;
        }
      }
    }
  }
  // get length of output data
  int output_size = 0;
  uint64_t last = base_track[base_array_size-1];
  if (last & 0xFF000000)
    output_size = base_array_size * 4;
  else if (last & 0xFF0000)
    output_size = base_array_size * 4 - 1;
  else if (last & 0xFF00)
    output_size = base_array_size * 4 - 2;
  else
    output_size = base_array_size * 4 - 3;
  // convert base
  for (int i = 0; i < input_size; i++)
  {
    if (base58_input[i] >= sizeof(base58_lookup) / sizeof(base58_lookup[0]))
      return false;
    int8_t digit = base58_lookup[base58_input[i]];
    if (digit == -1)
      return false;
    // multiply baseArray with 58
    for (int b = base_array_size-1; b >= 0; b--)
    {
      uint64_t mwc = (uint64_t) base_array[b] * 58ULL;
      base_array[b] = (uint32_t) (mwc & 0xFFFFFFFFUL);
      mwc >>= 32;
      if (mwc != 0)
      {
        // add carry
        for (int carry_idx = b + 1; carry_idx < base_array_size; carry_idx++)
        {
          mwc += (uint64_t) base_array[carry_idx];
          base_array[carry_idx] = (uint32_t) (mwc & 0xFFFFFFFFUL);
          mwc >>= 32;
          if (mwc == 0)
            break;
        }
        if (mwc)
        {
          // extend
          base_array[base_array_size] = (uint32_t) mwc;
          base_array_size++;
        }
      }
    }
    // add base58 digit to baseArray with carry
    uint64_t awc = (uint64_t) digit;
    for (int b = 0; awc != 0 && b < base_array_size; b++)
    {
      awc += (uint64_t) base_array[b];
      base_array[b] = (uint32_t) (awc & 0xFFFFFFFFUL);
      awc >>= 32;
    }
    if (awc)
    {
      // extend
      base_array[base_array_size] = (uint32_t) awc;
      base_array_size++;
    }
  }
  *out_size = output_size;
  // write bytes to about
  for (int i = 0; i < output_size; i++)
    out[output_size - i - 1] = (uint8_t) (base_array[i>>2] >> 8 * (i & 3));
  return true;
}

/*
 * Converts a wallet address (any coin) to the coin-independent pubKeyHash
 */
bool address_decode(uint8_t* pub_key_hash, char* wallet_address, int offset)
{
  uint8_t wallet_address_raw[256];
  int wallet_address_raw_size;
  if (base58_decode(wallet_address_raw, &wallet_address_raw_size, wallet_address, strlen(wallet_address)) == false)
  {
    applog(LOG_WARNING, "Address %s is not correctly base58 encoded", wallet_address);
    return false;
  }
  // is length valid?
  if (wallet_address_raw_size != 24 + offset)
  {
    applog(LOG_WARNING, "Decoding address %s yields invalid number of bytes", wallet_address);
    return false;
  }
  // validate checksum
  uint8_t address_hash[32];
  sph_sha256_context s256c;
  sph_sha256_init(&s256c);
  sph_sha256(&s256c, wallet_address_raw, wallet_address_raw_size - 4);
  sph_sha256_close(&s256c, address_hash);
  sph_sha256_init(&s256c);
  sph_sha256(&s256c, address_hash, 32);
  sph_sha256_close(&s256c, address_hash);
  if (*(uint32_t*) (wallet_address_raw + 20 + offset) != *(uint32_t*) address_hash)
  {
    applog(LOG_WARNING, "Address %s is invalid", wallet_address);
    return false;
  }
  if (pub_key_hash != NULL)
    memcpy(pub_key_hash, wallet_address_raw + offset, 20);
  return true;
}



int add_var_int(uint8_t* msg, uint64_t var_int)
{
  int size = 0;
  if (var_int <= 0xfcU)
  {
    msg[0] = var_int & 0xff;
  }
  else if (var_int <= 0xffffU)
  {
    msg[0] = 0xfd;
    size = 2;
  }
  else if (var_int <= 0xffffffffU)
  {
    msg[0] = 0xfe;
    size = 4;
  }
  else
  {
    msg[0] = 0xff;
    size = 8;
  }
  var_int = htole64(var_int);
  memcpy(msg + 1, &var_int, size);
  return size + 1;
}

int add_block_height(uint8_t* msg, uint32_t height)
{
  int size = 4;
  if (height <= 0x7f)
    size = 1;
  else if (height <= 0x7fffU)
    size = 2;
  else if (height <= 0x7fffffU)
    size = 3;
  height = htole32(height);
  if (msg != NULL)
    memcpy(msg, &height, size);
  return size;
}

int add_int32(uint8_t* msg, int32_t val)
{
  val = htole32(val);
  memcpy(msg, &val, 4);
  return 4;
}

int add_int64(uint8_t* msg, int64_t val)
{
  val = htole64(val);
  memcpy(msg, &val, 8);
  return 8;
}


bool set_coinbasetxn(struct pool *pool, uint32_t height, uint64_t coinbasevalue, uint64_t coinbasefrvalue, const char *coinbasefrscript) {
  int offset = 0;
  int height_size = add_block_height(NULL, height);
  uint8_t raw_address[20];
  if (!address_decode(raw_address, strchr(pool->rpc_user, '.') + 1, 2))  // decode zcash address
    return false;
  pool->coinbase = realloc(pool->coinbase, 512 + pool->n2size);  // alloc some extra space

  offset += add_int32(pool->coinbase + offset, 1);  // version
  offset += add_var_int(pool->coinbase + offset, 1);  // number of inputs
  memset(pool->coinbase + offset, 0, 32);  // transaction id
  offset += 32;
  offset += add_int32(pool->coinbase + offset, 0xffffffff);  // output index
  if (height <= 0x10) {
    offset += add_var_int(pool->coinbase + offset, 1 + height_size + 4 + pool->n2size);
    pool->coinbase[offset++] = 0x50 + height;  // return OP_height
  }
  else {
    offset += add_var_int(pool->coinbase + offset, 2 + height_size + 4 + pool->n2size);
    offset += add_var_int(pool->coinbase + offset, height_size);
    offset += add_block_height(pool->coinbase + offset, height);
  }
  offset += add_var_int(pool->coinbase + offset, 4 + pool->n2size);
  pool->nonce2_offset = offset;
  offset += pool->n2size;
  offset += add_int32(pool->coinbase + offset, 0x4e614e2f);
  offset += add_int32(pool->coinbase + offset, 0xffffffff);  // sequence number

  bool has_fr = (coinbasefrvalue != 0);
  offset += add_var_int(pool->coinbase + offset, has_fr ? 2 : 1);  // number of outputs
  offset += add_int64(pool->coinbase + offset, coinbasevalue);  // coinbasevalue
  
  offset += add_var_int(pool->coinbase + offset, 25);  // size of script
  pool->coinbase[offset++] = 0x76;  // OP_DUP
  pool->coinbase[offset++] = 0xa9;  // OP_HASH160
  offset += add_var_int(pool->coinbase + offset, 20);  // size of pubkeyHash
  memcpy(pool->coinbase + offset, raw_address, 20);  // pubkeyHash
  offset += 20;
  pool->coinbase[offset++] = 0x88;  // OP_EQUALVERIFY
  pool->coinbase[offset++] = 0xac;  // OP_CHECKSIG
  
  /*
  char pubkey_str[] = "03556ae4825538153f719ef90a187eafae03ef1884dc09399c8a2de8929c2cd798";
  uint8_t pubkey[33];
  hex2bin(pubkey, pubkey_str, 33);
  offset += add_var_int(pool->coinbase + offset, 35);  // size of script
  offset += add_var_int(pool->coinbase + offset, 33);  // size of pubkey
  memcpy(pool->coinbase + offset, pubkey, 33);  // pubkey
  offset += 33;
  pool->coinbase[offset++] = 0xac;  // OP_CHECKSIG 
  */
  if (has_fr) {
    int len = strlen(coinbasefrscript) / 2;
    offset += add_int64(pool->coinbase + offset, coinbasefrvalue);  // founders reward
    offset += add_var_int(pool->coinbase + offset, len);  // size of founders script
    hex2bin(pool->coinbase + offset, coinbasefrscript, len);  // founders script
    offset += len;
  }
  offset += add_int32(pool->coinbase + offset, 0);  // lock time
  pool->coinbase_len = offset;
  
  return true;
}

