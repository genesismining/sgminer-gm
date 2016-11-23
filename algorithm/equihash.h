#ifndef __EQUIHASH_H
#define __EQUIHASH_H

#include <stdint.h>
#include "miner.h"
#include "kernel/equihash-param.h"

uint32_t equihash_verify_sol(struct work *work, sols_t *sols, int sol_i);
void equihash_calc_mid_hash(uint64_t[8], uint8_t*);
void equihash_regenhash(struct work *work);
int64_t equihash_scanhash(struct thr_info *thr, struct work *work, int64_t *last_nonce, int64_t __maybe_unused max_nonce);

#endif		// __EQUIHASH_H
