#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef int64_t block;
/* B is the base of the bignum system, it has to be an exponention 2 */
#define B 16777216
#define E 24       // B = 2^E, E = 1, 2, ..., 31
#define MASK 0xffffff

typedef struct {
  int sign;
  int size;
  block *tab;
} bignum;

bignum bignum_from_string(char * str);
bignum bignum_add(bignum a, bignum b);
bignum bignum_sub(bignum a, bignum b);
bignum bignum_mult(bignum a, bignum b);

bignum bignum_rand(int len);

// other functions
bignum bignum_from_int(int d);

int bignum_is_zero(bignum a);
int bignum_is_one(bignum a);
int bignum_length(bignum a);
int bignum_cmp(bignum a, bignum b);

bignum bignum_lshift(bignum a, int k);
bignum bignum_rshift(bignum a, int k);

void bignum_copy(bignum *dest, bignum src);
void bignum_dump(bignum a);

#endif
