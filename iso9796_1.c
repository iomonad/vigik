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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "iso9796_1.h"

#define ASSERT_OR_DIE(assertion, rcode) if(!(assertion)) {exit(rcode);}

static uint8_t s_shadows[] = {
    0xe, 0x3, 0x5, 0x8, 0x9, 0x4, 0x2, 0xf,
    0x0, 0xd, 0xb, 0x6, 0x7, 0xa, 0xc, 0x1
};

static uint8_t s_inverse[] = {
    0x8, 0xf, 0x6, 0x1, 0x5, 0x2, 0xb, 0xc,
    0x3, 0x4, 0xd, 0xa, 0xe, 0x9, 0x0, 0x7
};


uint32_t iso9796_1_get_blk_size(ISO9796D1Encoding *enc) {
    return (enc->bit_size + 7) / 8;
}

int32_t iso9796_1_encode(ISO9796D1Encoding *enc, uint8_t in[], uint32_t in_off,
                         uint32_t in_len, uint8_t block[], uint32_t block_length,
                         uint32_t *real_block_length) {
    int err = 0;
    ASSERT_OR_DIE(enc != NULL, ERROR_D1_INVALID_ARG1);
    ASSERT_OR_DIE(block != NULL, ERROR_D1_INVALID_ARG1);
    ASSERT_OR_DIE(in_off < in_len, ERROR_D1_INVALID_ARG1);
    ASSERT_OR_DIE(block_length > 0, ERROR_D1_INVALID_ARG1);
    ASSERT_OR_DIE(real_block_length != NULL, ERROR_D1_INVALID_ARG1);

    uint32_t r = enc->pad_bits + 1;
    uint32_t z = in_len;
    uint32_t t = (enc->bit_size + 13) / 16;

    for (uint32_t i = 0; i < t; i += z) {
        if (i > (t - z)) {
            memcpy(block + block_length - t, in + in_off + in_len - (t - i), t - i);
        } else {
            memcpy(block + block_length - (i + z), in + in_off, z);
        }
    }
    ASSERT_OR_DIE(block_length >= 2 * t, ERROR_D1_INVALID_ARG3);
    for (uint32_t i = block_length - 2 * t; i != block_length; i += 2) {
        uint8_t val = block[block_length - t + i / 2];
        block[i] =
            (uint8_t)((s_shadows[(val & 0xff) >> 4] << 4) | s_shadows[val & 0x0f]);
        block[i + 1] = val;
    }

    ASSERT_OR_DIE(block_length >= 2 * z, ERROR_D1_INVALID_ARG3);
    block[block_length - 2 * z] ^= r;
    block[block_length - 1] = (uint8_t)((block[block_length - 1] << 4) | 0x06);

    int maxBit = (8 - (enc->bit_size - 1) % 8);
    int offset = 0;

    if (maxBit != 8) {
        block[0] &= (0xff >> maxBit);
        block[0] |= (0x80 >> maxBit);
    } else {
        block[0] = 0x00;
        block[1] |= 0x80;
        offset = 1;
    }
    if (offset == 1) {
        memmove(block, block + 1, block_length - 1);
        *real_block_length = block_length - 1;
    } else {
        *real_block_length = block_length;
    }

    err = 0;
    return err;
}

int32_t  iso9796_1_decode(ISO9796D1Encoding *enc, uint8_t block[], uint32_t block_length,
                          uint8_t new_block[], uint32_t *new_block_length) {
    int err = 0;
    ASSERT_OR_DIE(block != NULL, ERROR_D1_INVALID_ARG2);
    ASSERT_OR_DIE(new_block != NULL, ERROR_D1_INVALID_ARG2);
    ASSERT_OR_DIE(new_block_length != NULL && *new_block_length == block_length,
           ERROR_D1_INVALID_ARG2);

    uint32_t r = 1;
    uint32_t t = (enc->bit_size + 13) / 16;

    //int8_t *ptr = (int8_t *)block;
    if (block[0] == 0) {
        memmove(block, block + 1, block_length - 1);
        block_length -= 1;
    }
    ASSERT_OR_DIE((block[block_length - 1] & 0x0f) == 0x6, ERROR_D1_NOT_SIX);

    block[block_length - 1] =
        (uint8_t)(((block[block_length - 1] & 0xff) >> 4) |
                  ((s_inverse[(block[block_length - 2] & 0xff) >> 4]) << 4));

    block[0] = (uint8_t)((s_shadows[(block[1] & 0xff) >> 4] << 4) |
                         s_shadows[block[1] & 0x0f]);
    bool boundaryFound = false;
    int boundary = 0;

    assert(block_length >= 2 * t);
    int lower_bound = (int)(block_length - 2 * t);
    for (int i = block_length - 1; i >= lower_bound; i -= 2) {
        int val =
            ((s_shadows[(block[i] & 0xff) >> 4] << 4) | s_shadows[block[i] & 0x0f]);
        if (((block[i - 1] ^ val) & 0xff) != 0) {
            if (!boundaryFound) {
                boundaryFound = true;
                r = (block[i - 1] ^ val) & 0xff;
                boundary = i - 1;
            } else {
                err = ERROR_D1_INVALID_TSUM;
                goto exit;
            }
        }
    }
    block[boundary] = 0;

    *new_block_length = (block_length - boundary) / 2;

    for (uint32_t i = 0; i < *new_block_length; i++) {
        new_block[i] = block[2 * i + boundary + 1];
    }
    enc->pad_bits = r - 1;

    err = 0;
 exit:
    return err;
}
