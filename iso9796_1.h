/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * (C) Author: iomonad <iomonad@riseup.net>
 */

#ifndef __ISO_9796_1_H__
#define __ISO_9796_1_H__

#include <stdint.h>
#include <stdlib.h>

typedef struct {
    int32_t bit_size;  // same as key size, 512, 1024, 2048, etc.
    int32_t pad_bits;  // always set it to 4
} ISO9796D1Encoding;

uint32_t iso9796_1_get_blk_size(ISO9796D1Encoding *enc);
int32_t  iso9796_1_encode(ISO9796D1Encoding *enc, uint8_t in[], uint32_t in_off,
                          uint32_t in_len, uint8_t block[], uint32_t block_length,
                          uint32_t *real_block_length);
int32_t  iso9796_1_decode(ISO9796D1Encoding *enc, uint8_t block[], uint32_t block_length,
                          uint8_t new_block[], uint32_t *new_block_length);

#define ERROR_D1_INVALID_ARG1 (-51)
#define ERROR_D1_INVALID_ARG2 (-52)
#define ERROR_D1_INVALID_ARG3 (-53)
#define ERROR_D1_INVALID_ARG4 (-54)
#define ERROR_D1_INVALID_ARG5 (-55)
#define ERROR_D1_INVALID_ARG6 (-56)
#define ERROR_D1_INVALID_ARG7 (-57)
#define ERROR_D1_INVALID_TSUM (-58)
#define ERROR_D1_NOT_SIX (-59)

#endif /* __ISO_9796_1_H__ */
