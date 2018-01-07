#ifndef SKEINCOIN_H
#define SKEINCOIN_H

#include "miner.h"

extern void skeincoin_prepare_work(dev_blk_ctx *blk, uint32_t *state, uint32_t *data);
extern void skeincoin_regenhash(struct work *work);

#endif /* SKEINCOIN_H */
