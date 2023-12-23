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

#ifndef __VIGIK_H__
#define __VIGIK_H__

#include <stdlib.h>

#define MF1S50YYX_BLOCK_SIZE   16
#define MF1S50YYX_SECTOR_COUNT 16
#define MF1S50YYX_SECTOR_SIZE  4

#define MF1S50YYX_MEMORY_SIZE  1024

static uint8_t VIGIK_CRYPTO_AZERO_KEY[6] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5
};

static uint8_t VIGIK_CRYPTO_A_KEY[6] = {
    0x31, 0x4B, 0x49, 0x47, 0x49, 0x56
};

static uint8_t VIGIK_CRYPTO_B_KEY[6] = {
    0xEF, 0x61, 0xA3, 0xD4, 0x8E, 0x2A
};

typedef enum {
    Poste_Service_Universel = 0x000007AA,
    Poste_Autres_Services   = 0x000007AB,
    Edf_Gdf                 = 0x000007AC,
    France_Telecom          = 0x000007AD,
    Service_Urgence         = 0x000007B5,
    Service_Securite        = 0x000007B6,

    Custom                  = 0x0000FFFF
} Vigik_Service;

typedef struct {
    uint8_t  *MF1S50YYX_memory_slot;

    uint8_t  *MF1S50YYX_uid;
    uint8_t  *MF1S50YYX_atqa;
    uint8_t  *MF1S50YYX_sak;

    Vigik_Service service;

    uint8_t  *vigik_access_date;
    uint8_t  *vigik_loading_date;
    uint8_t  *vigik_access_counter;
} Vigik_Cartdrige;


typedef struct {
    const char *cmd;
    void  (*handler)(void);
} cmd_dispatcher;

#endif	/* __VIGIK_H__ */
