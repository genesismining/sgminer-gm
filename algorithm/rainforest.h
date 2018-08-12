#ifndef RAINFOREST_H
#define RAINFOREST_H

#include "miner.h"
#define RF256_SCRATCHBUF_SIZE 4096
extern int rainforest_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce);
extern void rainforest_regenhash(struct work *work);
extern void rainforest_precompute(const void *in, void *out);

#endif /* RAINFOREST_H */
