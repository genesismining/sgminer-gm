#ifndef __CRYPTONIGHT_H
#define __CRYPTONIGHT_H

typedef struct _CryptonightCtx
{
  uint64_t State[25];
  uint64_t Scratchpad[1 << 18];
} CryptonightCtx;

static inline int cryptonight_variant(struct work *work) {
  return (((work->cryptonight_version > 1) && (((uint8_t *)work->data)[0] >= work->cryptonight_version)) ? ((uint8_t *)work->data)[0] - work->cryptonight_version + 1 : 0 );
}

void cryptonight_regenhash(struct work *work);

#endif
