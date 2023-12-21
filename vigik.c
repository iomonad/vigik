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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "vigik.h"

static void usage(char *argv[]) {
     fprintf(stderr, "%s -k <private-key>\n");
}

int main(int argc, char *argv[]) {
     int  c;
     char *pk = NULL;

     while ((c = getopt (argc, argv, "k:")) != -1) {
	  switch (c) {
	  case 'k':
	       pk = optarg;
	       break;
	  case '?':
	       if (optopt == 'c') {
		    fprintf(stderr, "option -%c requires argument\n", optopt);
		    return 1;
	       }
	  default:
	       return 1;
	  }
     }

     if (pk == NULL) {
	  usage();

	  return 1;
     }

     fprintf(stdout, "using private key path '%s'\n", pk);
     return 0;
}
