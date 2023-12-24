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
#include "iso9796_1.h"

#define VERSION "0.0.1"

static bool dry_run = false, debug = false, memory_view = false, apply_padding = false;
static char *pk = NULL, *dump = NULL,
    *output = NULL, cmd_root[32], cmd_sub[32];
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
	printf("[E] %s: malloc() error\n", __func__);
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
	printf("[W] %s: buffer already released\n", __func__);
	return false;
    }
}

static bool mf1s50yyx_fill_memory_slot(const char *path, uint8_t *slot) {

    unsigned long len;
    FILE *fp = fopen(path, "rb");

    if (fp == NULL) {
	printf("[E] %s: %s bad dump input\n" CRESET, RED,  __func__);
	exit(EXIT_FAILURE);
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    rewind(fp);

    fread(slot, len, 1, fp);

    if (len != MF1S50YYX_MEMORY_SIZE) {
	printf("[E] %s: %sbad dump memory size '%ld', expected %d for MF1S50YYX\n" CRESET,
               __func__,
	       RED,
	       len, MF1S50YYX_MEMORY_SIZE);
	exit(EXIT_FAILURE);
    }
    fclose(fp);
    return true;
}

static uint8_t *mf1s50yyx_read_range(const uint8_t *memory,
				     size_t start, size_t end) {
    size_t range = (end - start);
    uint8_t *spectrum = NULL;

    if ((spectrum = (uint8_t*)malloc(range *sizeof(uint8_t))) == NULL) {
	fprintf(stderr, CRESET "[E] %s: %srange reader allocator failure\n" CRESET,  __func__, YEL);
	exit(EXIT_FAILURE);
    }

    return memcpy(spectrum, (memory + start), range);
}

static void mf1s50yyx_write_range(uint8_t *memory, size_t start,
                                  size_t end, const uint8_t *mutated_buffer) {
    size_t range = (end - start);

    if (memory == NULL || mutated_buffer == NULL) {
        return ;
    }

    if ((end - start) != (sizeof(mutated_buffer) / sizeof(uint8_t))) {
        fprintf(stdout, "[W] %s: %sbuffer size is different from write range\n" CRESET,
                __func__, YEL);
    }

    memcpy((memory + start), mutated_buffer, range);
}

void mf1s50yyx_mutate_range(uint8_t *memory, size_t start,
                                   size_t end, void (*mutator_kb)(uint8_t*)) {
    uint8_t *to_mutate = mf1s50yyx_read_range(memory, start, end);

    mutator_kb(to_mutate);
    mf1s50yyx_write_range(memory, start, end, to_mutate);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static RSA *vigik_crypto_load_private_key(const char *path) {
    RSA *private_key = NULL;
    FILE *fp = NULL;

    if ((fp = fopen(path, "r")) == NULL) {
        fprintf(stdout, "[W] %s: %sissue with private key loading\n" CRESET,
                __func__, YEL);

        exit(EXIT_FAILURE);
    }
    private_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (debug) {
        fprintf(stdout, "[I] %s: loaded RSA private key %s%s\n" CRESET,
                __func__, BLU, path);
    }
    return private_key;
}

static void vigik_crypto_release_private_key(RSA *key) {
    RSA_free(key);

    return ;
}

static void vigik_actualize_fields(Vigik_Cartdrige *cartdrige) {
    return;
}

static void vigik_echo_rsa_signature(unsigned char *signed_sector) {
    if (signed_sector != NULL) {
        printf("\n-----BEGIN RSA SIGNATURE-----");
        for (size_t i = 0; signed_sector[i] != 0x0; i++) {
            if ((i % 16) == 0) {
                printf("\n");
            }
            printf("%.02X ", signed_sector[i]);
        }
        printf("\n-----END RSA SIGNATURE-----\n\n");
    }
}

static void vigik_crypto_iso_9796_1_padding(unsigned char **encrypted_buffer) {
    ISO9796D1Encoding enc;

    enc.pad_bits = 8;
    enc.bit_size = 1024;

    uint32_t block_length = iso9796_1_get_blk_size(&enc);
    uint32_t real_block_length = block_length;

    uint8_t block[block_length];

    if (iso9796_1_encode(&enc, *encrypted_buffer, 0,
                         sizeof(*encrypted_buffer), block, block_length,
                         &real_block_length)
        < 0) {
        printf("[E] %s: %s error while encoding RSA signature\n" CRESET
               , __func__, RED);
        exit(EXIT_FAILURE);
    } else {
        if (debug) {
            vigik_echo_rsa_signature((unsigned char *)block);
        }

        if (real_block_length != block_length) {
            printf("[W] %s: %spadding block size divergences %d %d\n" CRESET, __func__, RED, real_block_length, block_length);
        }
        memcpy(*encrypted_buffer, block, real_block_length);
    }
}

static void vigik_crypto_sign_buffer(RSA *pk, const uint8_t *buffer, size_t buff_size,
                                     unsigned char **buffer_encrypted,
                                     size_t *lread) {
    EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY   *priKey  = EVP_PKEY_new();

    EVP_PKEY_assign_RSA(priKey, pk);

    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
        fprintf(stderr, "[E] %s: rsa sign init\n", __func__);
        return ;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, buffer, buff_size) <= 0) {
        fprintf(stderr, "[E] %s: rsa digest sign update\n", __func__);
        return ;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, lread) <=0) {
        fprintf(stderr, "[E] %s: rsa digest final\n", __func__);
        return ;
    }

    *buffer_encrypted = (unsigned char*)malloc(*lread);
    if (EVP_DigestSignFinal(m_RSASignCtx, *buffer_encrypted, lread) <= 0) {
        fprintf(stderr, "[E] %s: rsa digest final\n", __func__);
        return ;
    }

    EVP_MD_CTX_free(m_RSASignCtx);
}

#pragma GCC diagnostic pop

static void vigik_sign_sectors(RSA *pk, Vigik_Cartdrige *cartdrige) {
    uint8_t *vigik_sectors = NULL;
    unsigned char *signed_vigik_sector = NULL;
    size_t signed_buffer_size;

    vigik_sectors = mf1s50yyx_read_range(cartdrige->MF1S50YYX_memory_slot,
                                         0x40, 0x80);

    vigik_crypto_sign_buffer(pk, vigik_sectors,
                             (MF1S50YYX_SECTOR_SIZE * MF1S50YYX_BLOCK_SIZE),
                             &signed_vigik_sector,
                             &signed_buffer_size);

    if (signed_buffer_size != 0x80) {
        fprintf(stderr, "[W] %s: %sRSA signature don't have expected size (%ld bits)\n"
                CRESET, __func__, RED, signed_buffer_size);
    }

    vigik_echo_rsa_signature(signed_vigik_sector);

    if (apply_padding) {
        vigik_crypto_iso_9796_1_padding(&signed_vigik_sector);
    }

    for (size_t s = 0x2; s < 0x5; s++) {
        mf1s50yyx_write_range(cartdrige->MF1S50YYX_memory_slot,
                              ((MF1S50YYX_SECTOR_SIZE * MF1S50YYX_BLOCK_SIZE) * s),
                              ((MF1S50YYX_SECTOR_SIZE * MF1S50YYX_BLOCK_SIZE) * s) + (0x3 * MF1S50YYX_BLOCK_SIZE),
                              signed_vigik_sector + ((MF1S50YYX_BLOCK_SIZE * 3) * (s - 0x2)));
    }

}

//
// VIGIK OPERATIONS
//

static Vigik_Cartdrige *vigik_allocate_cartdrige(const char *path) {
    Vigik_Cartdrige *cartdrige = NULL;

    fprintf(stdout, "[I] %s: allocating cartdrige from%s %s\n" CRESET, __func__, YEL, path);

    if ((cartdrige = (Vigik_Cartdrige*)malloc(sizeof(Vigik_Cartdrige))) == NULL) {
	fprintf(stderr, "[E] %s: cartdrige allocation\n", __func__);
	exit(EXIT_FAILURE);
    }

    cartdrige->MF1S50YYX_memory_slot = mf1s50yyx_allocate_memory_slot();

    if (!mf1s50yyx_fill_memory_slot(path, cartdrige->MF1S50YYX_memory_slot)) {
	fprintf(stderr, "[E] %s: withcartdrige->MF1S50YYX_memory_slot fill\n", __func__);
	exit(EXIT_FAILURE);
    }

    cartdrige->MF1S50YYX_uid = NULL;
    cartdrige->MF1S50YYX_atqa = NULL;
    cartdrige->MF1S50YYX_sak = NULL;

    return cartdrige;
}

Vigik_Cartdrige *vigik_duplicate_cartdrige(const Vigik_Cartdrige *cartdrige) {
    Vigik_Cartdrige *copy = NULL;

    if (cartdrige == NULL) {
	return NULL;
    }

    if ((copy = (Vigik_Cartdrige*)malloc(sizeof(Vigik_Cartdrige))) == NULL) {
	fprintf(stderr, "[E] %s: vigik cartdrige allocation\n", __func__);
	exit(EXIT_FAILURE);
    }

    copy->MF1S50YYX_memory_slot = mf1s50yyx_allocate_memory_slot();
    copy->MF1S50YYX_memory_slot =
	memcpy(copy->MF1S50YYX_memory_slot,
	       cartdrige->MF1S50YYX_memory_slot, MF1S50YYX_MEMORY_SIZE);

    copy->MF1S50YYX_uid = cartdrige->MF1S50YYX_uid;
    copy->MF1S50YYX_atqa = cartdrige->MF1S50YYX_atqa;
    copy->MF1S50YYX_sak = cartdrige->MF1S50YYX_sak;
    copy->service = cartdrige->service;
    return copy;
}

static void vigik_release_cartdrige(Vigik_Cartdrige *cartdrige) {
    if (cartdrige == NULL) {
	return ;
    }

    mf1s50yyx_release_memory_slot(cartdrige->MF1S50YYX_memory_slot);
    cartdrige->MF1S50YYX_memory_slot = NULL;

    free(cartdrige->MF1S50YYX_uid);
    free(cartdrige->MF1S50YYX_atqa);
    free(cartdrige->MF1S50YYX_sak);
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

static void vigik_diff_cartdrige_memory(FILE *fd, Vigik_Cartdrige *original,
                                        Vigik_Cartdrige *next, size_t sectors) {
    for (size_t sector = 0; sector < sectors; sector++) {
	for (size_t zSector = 0 ; zSector < MF1S50YYX_SECTOR_SIZE; zSector++) {
	    fprintf(fd, CRESET);
	    fprintf(fd, "%.02ld.%ld/%d.%.02ld\t", sector, zSector + 1, MF1S50YYX_SECTOR_SIZE,
		    (sector * MF1S50YYX_SECTOR_SIZE) + zSector);
	    for (size_t bIterator = 0; bIterator < MF1S50YYX_BLOCK_SIZE; bIterator++) {
		size_t real = (sector * (MF1S50YYX_SECTOR_SIZE * MF1S50YYX_BLOCK_SIZE))
		    + (zSector * MF1S50YYX_BLOCK_SIZE) + bIterator;
                uint8_t a = original->MF1S50YYX_memory_slot[real];
                uint8_t b = next->MF1S50YYX_memory_slot[real];
		fprintf(fd, "%s%.02X%s ", ((a != b) ? GRN : BLKHB), b, CRESET);
	    }
	    fprintf(fd, "\n");
	}
    }

    if (sectors != MF1S50YYX_SECTOR_COUNT) {
        printf("\t\t ... truncated\n");
    }
}

static void vigik_verify_keys(Vigik_Cartdrige *cartdrige) {
    fprintf(stdout, "[I] %s: checking memory keys:" CRESET, __func__);
    if (debug) {
	printf("\n");
    }
    for (size_t sector = 0; sector < MF1S50YYX_SECTOR_COUNT; sector++) {

	size_t key_sector = (sector * MF1S50YYX_SECTOR_SIZE) + 4;
	size_t key_memory_segment = ((MF1S50YYX_BLOCK_SIZE * (key_sector - 1)) + 0x0);

	if (debug) {
	    printf("[C] sector keys:%s %.02lX " CRESET, BLU, sector);
	}

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
	if (debug) {
	    fprintf(stdout, GRN "A/B - OK\n" CRESET);
	}
    }
    if (!debug) {
	fprintf(stdout, GRN " VALID\n" CRESET);
    }
    printf(CRESET);
}

static void vigik_inspect_cartdrige(Vigik_Cartdrige *cartdrige) {
    vigik_verify_keys(cartdrige);
}

static void vigik_read_properties(Vigik_Cartdrige *cartdrige) {

    if ((cartdrige->MF1S50YYX_uid =
	 mf1s50yyx_read_range(cartdrige->MF1S50YYX_memory_slot, 0x0, 0x4)) != NULL) {
	fprintf(stdout, "[I] %s: detected Card UID " GRN, __func__);
	for (size_t i = 0; i < 4; i++) {
	    fprintf(stdout, "%.02X", cartdrige->MF1S50YYX_uid[i]);
	}
	fprintf(stdout, CRESET"\n");
    }

    if ((cartdrige->MF1S50YYX_sak =
	 mf1s50yyx_read_range(cartdrige->MF1S50YYX_memory_slot, 0x5, 0x6)) != NULL) {
	fprintf(stdout, "[I] %s: detected Card SAK " GRN, __func__);
	fprintf(stdout, "%.02X", cartdrige->MF1S50YYX_sak[0]);
	fprintf(stdout, CRESET"\n");
    }

    if ((cartdrige->MF1S50YYX_atqa =
	 mf1s50yyx_read_range(cartdrige->MF1S50YYX_memory_slot, 0x6, 0x8)) != NULL) {
	fprintf(stdout, "[I] %s: detected Card ATQA " GRN, __func__);
	fprintf(stdout, "%.02X", cartdrige->MF1S50YYX_atqa[0]);
	fprintf(stdout, "%.02X", cartdrige->MF1S50YYX_atqa[1]);
	fprintf(stdout, CRESET"\n");
    }

    uint8_t *service
	= mf1s50yyx_read_range(cartdrige->MF1S50YYX_memory_slot,
			       (MF1S50YYX_BLOCK_SIZE * 5),
			       ((MF1S50YYX_BLOCK_SIZE * 5) + 0x4));
    if (strcmp((char*)service, (char*)"\xAA\x07") == 0) {
	cartdrige->service = Poste_Service_Universel;
	fprintf(stdout, "[I] %s: detected Card Service: %sPoste Service Universel\n" CRESET, __func__, GRN);
    } else if (strcmp((char*)service, (char*)"\xAB\x07") == 0) {
	cartdrige->service = Poste_Autres_Services;
	fprintf(stdout, "[I] %s: detected Card Service: %sPoste Autres Service\n" CRESET, __func__, GRN);
    } else if (strcmp((char*)service, (char*)"\xAC\x07") == 0) {
	cartdrige->service = Edf_Gdf;
	fprintf(stdout, "[I] %s: detected Card Service: %sEDF/GDF\n" CRESET, __func__, GRN);
    } else if (strcmp((char*)service, (char*)"\xAD\x07") == 0) {
	cartdrige->service = France_Telecom;
	fprintf(stdout, "[I] %s: detected Card Service: %sFrance Telecom\n" CRESET, __func__, GRN);
    } else if (strcmp((char*)service, (char*)"\xA5\x07") == 0) {
	cartdrige->service = Service_Urgence;
	fprintf(stdout, "[I] %s: detected Card Service: %sService Urgence\n" CRESET, __func__, GRN);
    } else if (strcmp((char*)service, (char*)"\xA6\x07") == 0) {
	cartdrige->service = Service_Securite;
        fprintf(stdout, "[I] %s: detected Card Service: %sService Securite\n" CRESET, __func__,  GRN);
    } else {
	cartdrige->service = Custom;
        fprintf(stdout, "[W] %s: detected %sCustom Card Service\n" CRESET, __func__,  YEL);
    }
    free(service);
}

//
// ENTRYPOINT
//

void mutate_uid(uint8_t *data) {
    bzero(data, 4);
}

static void vigik_process_signature(void) {
    if (dump == NULL || output == NULL || pk == NULL) {
        fprintf(stderr, "[E] %s: %smissing required arguments [-kdo]\n"
                CRESET, __func__, RED);
        exit(1);
    }
    RSA *private_key = NULL;
    Vigik_Cartdrige *cartdrige = NULL, *next_cartdrige = NULL;

    private_key = vigik_crypto_load_private_key(pk);
    cartdrige = vigik_allocate_cartdrige(dump);

    vigik_read_properties(cartdrige);
    vigik_inspect_cartdrige(cartdrige);

    if (memory_view) {
	vigik_dump_cartdrige_memory(stdout, cartdrige);
    }

    next_cartdrige = vigik_duplicate_cartdrige(cartdrige);

    vigik_actualize_fields(next_cartdrige);
    vigik_sign_sectors(private_key, next_cartdrige);

    if (memory_view) {
        vigik_dump_cartdrige_memory(stdout, next_cartdrige);
    }

    vigik_diff_cartdrige_memory(stdout, cartdrige, next_cartdrige, 5);

    vigik_crypto_release_private_key(private_key);
    vigik_release_cartdrige(cartdrige);
    vigik_release_cartdrige(next_cartdrige);
}

static void usage(char *argv[]) {
    fprintf(stderr, "Vigik v%s\n\n", VERSION);
    fprintf(stderr, "Signature: %s sign -k private.key -i mifare_dump.bin -o new_signed_memory.bin\n", argv[0]);
    fprintf(stderr, "Generate: %s generate -k private.key -o generated.bin\n\nOptions:\n", argv[0]);
    fprintf(stderr, "   -k %sPrivate key file\n" CRESET, BLU);
    fprintf(stderr, "   -i %sProxmark3 binary dump\n" CRESET, BLU);
    fprintf(stderr, "   -o %sOutput file to produce\n" CRESET, BLU);
    fprintf(stderr, "   -v %sDump memory to STDOUT\n" CRESET, BLU);
    fprintf(stderr, "   -d %sEnable debbuging\n" CRESET, BLU);
    fprintf(stderr, "   -c %sActivate dry-run mode\n" CRESET, BLU);
    fprintf(stderr, "   -h %sShow this help\n" CRESET, BLU);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    int  c, idx = 0;
    cmd_dispatcher dispatcher[] = {
        {"sign", &vigik_process_signature},
    };

    while ((c = getopt (argc, argv, "k:i:vhpcdo:")) != -1) {
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
	case 'v':
	    memory_view = true;
	    break;
	case 'd':
	    debug = true;
	    break;
	case 'c':
	    dry_run = true;
	    break;
        case 'p':
            apply_padding = true;
            break;
        case 'h':
            usage(argv);
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

    for (size_t index = optind; index < argc; index++) {
        if (idx == 0) {
            strcpy(cmd_root, argv[index]);
        } else if (idx == 1) {
            strcpy(cmd_sub, argv[index]);
        } else {
            break ;
        }
    }

    if (cmd_root[0] == 0x0) {
        usage(argv);
    }

    for (size_t i = 0; i < (sizeof(cmd_dispatcher) / sizeof(dispatcher[0])); i++) {
        if (strcmp(cmd_root, dispatcher[i].cmd) == 0) {
            dispatcher[i].handler();
            goto _cleanup;
        }
    }
    usage(argv);

 _cleanup:
    exit(EXIT_SUCCESS);
}
