#ifndef __EQUIHASH_H
#define __EQUIHASH_H

#include <stdint.h>
#include "miner.h"

void equihash_calc_mid_hash(uint64_t[8], uint8_t*);
int equihash_check_solutions(struct work*, uint32_t*, uint64_t*);
void equihash_regenhash(struct work *work);
int64_t equihash_scanhash(struct thr_info *thr, struct work *work, int64_t *last_nonce, int64_t __maybe_unused max_nonce);

#endif		// __EQUIHASH_H
