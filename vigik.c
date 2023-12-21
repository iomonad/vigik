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

static char *pk = NULL;
static char *dump = NULL;
static char *output = NULL;
static bool dry_run = false, debug = false;
static uint8_t *MF1S50YYX_memory_slot = NULL;
static uint8_t *MF1S50YYX_memory_slot_staging = NULL;

/* MIFARE OPERATIONS */

static bool mifare_reset_memory_slot(void *memory) {
     if (memory != NULL) {
	  bzero(memory, MF1S50YYX_MEMORY_SIZE);
	  return true;
     } else {
	  return false;
     }
}

static uint8_t *mifare_allocate_memory_slot() {
     uint8_t *slot = NULL;

     if ((slot = (uint8_t*)malloc(MF1S50YYX_MEMORY_SIZE * sizeof(uint8_t))) == NULL) {
	  printf("allocate: malloc() error\n");
	  return NULL;
     }

     mifare_reset_memory_slot(slot);
     return slot;
}

static bool mifare_release_memory_slot(uint8_t *buffer) {
     if (buffer != NULL) {
	  free(buffer);
	  return true;
     } else {
	  printf("vigik: buffer already released\n");
	  return false;
     }
}

static bool mifare_fill_memory_slot(uint8_t *buffer) {

     unsigned long len;
     FILE *fp = fopen(dump, "rb");

     if (fp == NULL) {
	  printf("input: bad dump input\n");

	  exit(EXIT_FAILURE);
     }

     fseek(fp, 0, SEEK_END);
     len = ftell(fp);
     rewind(fp);

     fread(buffer, len, 1, fp);

     if (len != MF1S50YYX_MEMORY_SIZE) {
	  printf("mifare: bad dump memory size (%ld)\n", len);
	  exit(EXIT_FAILURE);
     }
     fclose(fp);
     return true;
}


static void mifare_dump_memory(FILE *fd, uint8_t *buffer) {
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
		    uint8_t b = buffer[real];

		    fprintf(fd, "%02X ", b);
	       }
	       fprintf(fd, "\n");
	  }
     }
}


/* ENTRYPOINT  */

static bool vigik_process_signature(void) {

     /* Allocate Memory Cartdrige */
     MF1S50YYX_memory_slot = mifare_allocate_memory_slot();
     MF1S50YYX_memory_slot_staging = mifare_allocate_memory_slot();

     /* Fill up Proxmark dump to Memory Slot (initial one) */
     if (!mifare_fill_memory_slot(MF1S50YYX_memory_slot)) {
	  fprintf(stderr, "issue while filling memory\n");
	  exit(EXIT_FAILURE);
     }

     /* Make a hard copy of the memory cartdrige for
      * crypto alteration
      */
     MF1S50YYX_memory_slot_staging =
	  memcpy(MF1S50YYX_memory_slot_staging,
		 MF1S50YYX_memory_slot, MF1S50YYX_MEMORY_SIZE);

     if (debug) {
	  mifare_dump_memory(stdout, MF1S50YYX_memory_slot);
     }

     mifare_release_memory_slot(MF1S50YYX_memory_slot);
     mifare_release_memory_slot(MF1S50YYX_memory_slot_staging);

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
	  fprintf(stderr, "error while processing signature\n");
	  return 1;
     }
     return 0;
}
