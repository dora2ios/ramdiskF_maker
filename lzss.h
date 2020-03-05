// code by xerub's iloader: https://xerub.github.io/ios/iboot/2018/05/10/de-rebus-antiquis.html

#include <stdint.h>

uint32_t lzadler32(uint8_t *buf, int32_t len);
int decompress_lzss(uint8_t *dst, uint8_t *src, uint32_t srclen);
uint8_t *compress_lzss(uint8_t *dst, uint32_t dstlen, uint8_t *src, uint32_t srcLen);
