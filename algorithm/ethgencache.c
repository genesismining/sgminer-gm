#include <stdint.h>

#include "miner.h"
#include "sph/sph_keccak.h"
#include "algorithm/ethash.h"
#include "algorithm/eth-sha3.h"

typedef union node
{
  uint8_t bytes[16 * 4];
  uint32_t words[16];
  uint64_t double_words[16 / 2];
} node;

// Output (cache_nodes) MUST have at least cache_size bytes
static void EthGenerateCache(uint8_t *cache_nodes_in, const uint8_t *seedhash, uint64_t cache_size)
{
  uint32_t const num_nodes = (uint32_t)(cache_size / sizeof(node));
  node *cache_nodes = (node *)cache_nodes_in;
  
  SHA3_512(cache_nodes[0].bytes, seedhash, 32);
  
  for(uint32_t i = 1; i != num_nodes; ++i) {
    SHA3_512(cache_nodes[i].bytes, cache_nodes[i - 1].bytes, 64);
  }

  for(uint32_t j = 0; j < 3; j++) { // this one can be unrolled entirely, ETHASH_CACHE_ROUNDS is constant
    for(uint32_t i = 0; i != num_nodes; i++) {
      uint32_t const idx = cache_nodes[i].words[0] % num_nodes;
      node data;
      data = cache_nodes[(num_nodes - 1 + i) % num_nodes];
      for(uint32_t w = 0; w != 16; ++w) { // this one can be unrolled entirely as well
        data.words[w] ^= cache_nodes[idx].words[w];
      }
      
      SHA3_512(cache_nodes[i].bytes, data.bytes, sizeof(data));
    }
  }  
}


void eth_gen_cache(struct pool *pool) {
  size_t cache_size = EthGetCacheSize(pool->eth_cache.current_epoch);
  pool->eth_cache.dag_cache = realloc(pool->eth_cache.dag_cache, cache_size);
  EthGenerateCache(pool->eth_cache.dag_cache, pool->eth_cache.seed_hash, cache_size);
}
