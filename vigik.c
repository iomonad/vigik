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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "vigik.h"
#include "ansicode.h"

#define VERSION "0.0.1"

static bool dry_run = false, debug = false;
static char *pk = NULL, *dump = NULL, *output = NULL;

//
// MF1S50YYX Operations
//

static bool mf1s50yyx_reset_memory_slot(void *memory) {
     if (memory != NULL) {
	  bzero(memory, MF1S50YYX_MEMORY_SIZE);
	  return true;
     } else {
	  return false;
     }
}

static uint8_t *mf1s50yyx_allocate_memory_slot(void) {
     uint8_t *slot = NULL;

     if ((slot = (uint8_t*)malloc(MF1S50YYX_MEMORY_SIZE * sizeof(uint8_t))) == NULL) {
	  printf("allocate: malloc() error\n");
	  return NULL;
     }

     mf1s50yyx_reset_memory_slot(slot);
     return slot;
}

static bool mf1s50yyx_release_memory_slot(uint8_t *buffer) {
     if (buffer != NULL) {
	  free(buffer);
	  return true;
     } else {
	  printf("warn: buffer already released\n");
	  return false;
     }
}

static bool mf1s50yyx_fill_memory_slot(const char *path, uint8_t *slot) {

     unsigned long len;
     FILE *fp = fopen(path, "rb");

     if (fp == NULL) {
	  printf("error: bad dump input\n");

	  exit(EXIT_FAILURE);
     }

     fseek(fp, 0, SEEK_END);
     len = ftell(fp);
     rewind(fp);

     fread(slot, len, 1, fp);

     if (len != MF1S50YYX_MEMORY_SIZE) {
	  printf("error: bad dump memory size (%ld)\n", len);
	  exit(EXIT_FAILURE);
     }
     fclose(fp);
     return true;
}

//
// VIGIK OPERATIONS
//

static Vigik_Cartdrige *vigik_allocate_cartdrige(const char *path) {
     Vigik_Cartdrige *cartdrige = NULL;

     if ((cartdrige = (Vigik_Cartdrige*)malloc(sizeof(Vigik_Cartdrige))) == NULL) {
	  fprintf(stderr, "error: vigik cartdrige allocation\n");
	  exit(EXIT_FAILURE);
     }

     cartdrige->MF1S50YYX_memory_slot = mf1s50yyx_allocate_memory_slot();

     if (!mf1s50yyx_fill_memory_slot(path, cartdrige->MF1S50YYX_memory_slot)) {
	  fprintf(stderr, "error: cartdrige->MF1S50YYX_memory_slot fill\n");
	  exit(EXIT_FAILURE);
     }
     return cartdrige;
}

static Vigik_Cartdrige *vigik_duplicate_cartdrige(Vigik_Cartdrige *cartdrige) {
     Vigik_Cartdrige *copy = NULL;

     if (cartdrige == NULL) {
	  return NULL;
     }

     if ((copy = (Vigik_Cartdrige*)malloc(sizeof(Vigik_Cartdrige))) == NULL) {
	  fprintf(stderr, "error: vigik cartdrige allocation\n");
	  exit(EXIT_FAILURE);
     }

     copy->MF1S50YYX_memory_slot = mf1s50yyx_allocate_memory_slot();
     copy->MF1S50YYX_memory_slot =
	  memcpy(copy->MF1S50YYX_memory_slot,
		 cartdrige->MF1S50YYX_memory_slot, MF1S50YYX_MEMORY_SIZE);

     return copy;
}

static void vigik_release_cartdrige(Vigik_Cartdrige *cartdrige) {
     if (cartdrige == NULL) {
	  return ;
     }

     mf1s50yyx_release_memory_slot(cartdrige->MF1S50YYX_memory_slot);
     cartdrige->MF1S50YYX_memory_slot = NULL;

     free(cartdrige);
}

static void vigik_dump_cartdrige_memory(FILE *fd, Vigik_Cartdrige *cartdrige) {
     for (size_t sector = 0; sector < MF1S50YYX_SECTOR_COUNT; sector++) {
	  for (size_t zSector = 0 ; zSector < MF1S50YYX_SECTOR_SIZE; zSector++) {

	       fprintf(fd, CRESET);
	       fprintf(fd, "%.02ld.%ld/%d.%.02ld\t", sector, zSector + 1, MF1S50YYX_SECTOR_SIZE,
		       (sector * MF1S50YYX_SECTOR_SIZE) + zSector);

	       if (zSector == (MF1S50YYX_SECTOR_SIZE - 1)) {
		    fprintf(fd, YEL);
	       } else {
		    fprintf(fd, CRESET);
	       }

	       for (size_t bIterator = 0; bIterator < MF1S50YYX_BLOCK_SIZE; bIterator++) {
		    size_t real = (sector * (MF1S50YYX_SECTOR_SIZE * MF1S50YYX_BLOCK_SIZE))
			 + (zSector * MF1S50YYX_BLOCK_SIZE) + bIterator;
		    uint8_t b = cartdrige->MF1S50YYX_memory_slot[real];

		    fprintf(fd, "%02X ", b);
	       }
	       fprintf(fd, "\n");
	  }
     }
}

static void vigik_verify_keys(Vigik_Cartdrige *cartdrige) {
     for (size_t sector = 0; sector < MF1S50YYX_SECTOR_COUNT; sector++) {

	  size_t key_sector = (sector * MF1S50YYX_SECTOR_SIZE) + 4;
	  size_t key_memory_segment = ((MF1S50YYX_BLOCK_SIZE * (key_sector - 1)) + 0x0);

	  VIGIK_CRYPTO_B_KEY[0] = 0;
	  for (size_t i = 0; i < 6 ; i++) {

	       size_t b_offset = (i + 0xA);
	       if (((sector == 0) ? VIGIK_CRYPTO_AZERO_KEY[i]
		    : VIGIK_CRYPTO_A_KEY[i]) !=
		   cartdrige->MF1S50YYX_memory_slot[key_memory_segment + i]) {

		    printf("badkey A | sector %ld (diff %.02X|%.02X)\n",
			   sector, ((sector == 0) ? VIGIK_CRYPTO_AZERO_KEY[i]
				    : VIGIK_CRYPTO_A_KEY[i]),
			   cartdrige->MF1S50YYX_memory_slot[key_memory_segment + i]);

		    exit(EXIT_FAILURE);
	       }
	       if (VIGIK_CRYPTO_B_KEY[i]
		   != cartdrige->MF1S50YYX_memory_slot[key_memory_segment + b_offset]) {
		    printf("badkey b | sector %ld (diff %.02X|%.02X)\n",
			   sector, VIGIK_CRYPTO_B_KEY[i],
			   cartdrige->MF1S50YYX_memory_slot[key_memory_segment + b_offset]);

		    exit(EXIT_FAILURE);
	       }
	  }
     }
}

static void vigik_inspect_cartdrige(Vigik_Cartdrige *cartdrige) {
     vigik_verify_keys(cartdrige);
}

//
// ENTRYPOINT
//

static bool vigik_process_signature(void) {
     Vigik_Cartdrige *cartdrige = NULL, *cartdrige_staging = NULL;

     cartdrige = vigik_allocate_cartdrige(dump);
     cartdrige_staging = vigik_duplicate_cartdrige(cartdrige);

     vigik_inspect_cartdrige(cartdrige);

     if (debug) {
	  vigik_dump_cartdrige_memory(stdout, cartdrige);
     }

     vigik_release_cartdrige(cartdrige);
     vigik_release_cartdrige(cartdrige_staging);

     return true;
}

static void usage(char *argv[]) {
     fprintf(stderr, "Vigik v%s\n\n", VERSION);
     fprintf(stderr, "Usage: %s -k private.key -i mifare_dump.bin -o new_signed_memory.bin\n\nOptions:\n",
	     argv[0]);
     fprintf(stderr, "  -k  |  Private key to use\n");
     fprintf(stderr, "  -i  |  Proxmark3 Binary dump\n");
     fprintf(stderr, "  -o  |  Output dump\n");
     fprintf(stderr, "  -d  |  Enable debug\n");
     fprintf(stderr, "  -c  |  Enable Dryrun mode\n");
     fprintf(stderr, "\n");

     exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
     int  c;

     while ((c = getopt (argc, argv, "k:i:cdo:")) != -1) {
	  switch (c) {
	  case 'k':
	       pk = optarg;
	       break;
	  case 'i':
	       dump = optarg;
	       break;
	  case 'o':
	       output = optarg;
	       break;
	  case 'd':
	       debug = true;
	       break;
	  case 'c':
	       dry_run = true;
	       break;
	  case '?':
	       if (optopt == 'k' || optopt == 'i' || optopt == 'o') {
		    fprintf(stderr, "option -%c requires argument\n", optopt);
		    return 1;
	       }
	  default:
	       usage(argv);
	  }
     }

     if (pk == NULL || dump == NULL || output == NULL ) {
	  usage(argv);
     }

     if (!vigik_process_signature()) {
	  fprintf(stderr, "fatal: error processing signature\n");
	  return 1;
     }
     return 0;
}
