#ifndef __CRYPTONIGHT_H
#define __CRYPTONIGHT_H

typedef struct _CryptonightCtx
{
  uint64_t State[25];
  uint64_t Scratchpad[1 << 18];
} CryptonightCtx;

static inline int monero_variant(struct work *work) {
  return (work->is_monero && work->data[0] >= 7) ? work->data[0] - 6 : 0;
}

void cryptonight_regenhash(struct work *work);

#endif
