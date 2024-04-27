#include "bignum.h"

#define bignum_alloc malloc
#define bignum_free  free

bignum bignum_from_int(int d) {
  if (d < 0 || d > 9) {
    perror("Illegal input: input should be from 0 to 9.");
    exit(1);
  }

  bignum r;
  int i = 0;
  
  r.sign = 1;
  r.tab = (block *)bignum_alloc(sizeof(block) * 4);
  r.size = 1;
  while (d >= B) {
    r.size++;
    r.tab[i++] = d % B;
    d /= B;
  }
  r.tab[i] = d;

  return r;
}

bignum bignum_from_string(char * str) {
  int i, cnt;
  bignum b[11], r;
  block *tmp;

  // initialize 0, ..., 9
  for (i = 0; i < 10; i++)
    b[i] = bignum_from_int(i);

  // initialize 10 
  b[10].sign = 1;
  b[10].tab = (block *)bignum_alloc(sizeof(block) * 4);
  if (B > 10) {
    b[10].size = 1;
    b[10].tab[0] = 10;
  } else {
    i = 0;
    int ten = 10;
    b[10].size = 1;
    while (ten >= B) {
      b[10].size++;
      b[10].tab[i++] = ten % B;
      ten /= B;
    }
    b[10].tab[i] = ten;
  }
  
  cnt = 0;
  r.sign = 1;
  r.size = 1;
  r.tab = (block *)bignum_alloc(sizeof(block));
  r.tab[0] = 0;

  if (str[0] == '-') {
    cnt = 1;
  }

  tmp = r.tab;
  r = bignum_add(r, b[str[cnt++]-'0']);
  bignum_free(tmp);
  for (i = cnt; i < (int)strlen(str); i++) {
    int digit = str[i] - '0';
    if (digit < 0 || digit > 9) {
      perror(
        "Illegal input: input string should contain only numbers."
      );
      exit(0);
    }

    tmp = r.tab;
    r = bignum_mult(r, b[10]);
    bignum_free(tmp);

    tmp = r.tab;
    r = bignum_add(r, b[str[i]-'0']);
    bignum_free(tmp);
  }

  if (str[0] == '-')
    r.sign = -1;

  for (i = 0; i <= 10; i++) {
    free(b[i].tab);
    b[i].tab = NULL;
  }

  return r;
}

void bignum_dump(bignum a) {
  int i;
  if (B == 16) {
    if (a.sign == -1)
      printf("-");

    printf("0x");
    for (i = a.size-1; i >= 0; i--)
      printf("%lx", a.tab[i]);

    printf("\n");
  } else {
    for (i = a.size-1; i >= 0; i--)
      printf("%5d: %lu\n", i, a.tab[i]);

    printf("B = %d, %s\n", B, a.sign == 1 ? "positive" : "negtive");
  }
}

void bignum_copy(bignum *dest, bignum src) {
  if (dest == &src)
    return;

  *dest = src;
  dest->tab = (block *)bignum_alloc(dest->size * sizeof(block));
  memcpy(dest->tab, src.tab, dest->size*sizeof(block));
}

int bignum_is_zero(bignum a) {
  return (a.size == 1) && (a.tab[0] == 0);
}

int bignum_is_one(bignum a) {
  return (a.size == 1) && (a.sign == 1) && (a.tab[0] == 1);
}

/*
 * a < b, return -1
 * a = b, return 0
 * a > b, return 1
 */
int bignum_cmp(bignum a, bignum b) {
  if (a.sign == -1 && b.sign == 1)
    return -1;

  if (a.sign == 1 && b.sign == -1)
    return 1;

  if (a.sign == -1 && b.sign == -1) {
    a.sign = b.sign = 1;
    return bignum_cmp(b, a);
  }

  if (a.size < b.size)
    return -1;

  if (a.size > b.size)
    return 1;

  int i;
  for (i = a.size - 1; i >= 0; i--) 
    if (a.tab[i] < b.tab[i])
      return -1;
    else if (a.tab[i] > b.tab[i])
      return 1;

  return 0;
}

bignum bignum_lshift(bignum a, int k) {
  int i, len = bignum_length(a)+k;

  bignum res;
  res.sign = 1;
  res.size = (len/E) + ((len % E == 0) ? 0 : 1);
  res.tab = (block *)bignum_alloc((res.size) * sizeof(block));

  int m = k / E, n = k % E;
  for (i = 0; i < m; i++)
    res.tab[i] = 0;

  if (n == 0) 
    for (i = m; i < res.size; i++)
      res.tab[i] = a.tab[i-m];
  else {
    res.tab[m] = (((a.tab[0] << n) & (block)MASK));
    for (i = m+1; i < res.size-1; i++) {
      res.tab[i] = a.tab[i-m-1] >> (E-n);
      res.tab[i] |= (((a.tab[i-m] << n) & (block)MASK));
    }
    res.tab[i] = a.tab[i-m-1] >> (E-n);
    if (i-m < a.size)
      res.tab[i] |= (((a.tab[i-m] << n) & (block)MASK));
  }

  return res;
}

bignum bignum_rshift(bignum a, int k) {
  int i, len = bignum_length(a)-k;

  bignum res;
  res.sign = 1;

  if (len <= 0) {
    res.size = 1;
    res.tab = (block *)bignum_alloc(sizeof(block));
    res.tab[0] = 0;

    return res;
  } 
  
  res.size = (len / E) + ((len % E == 0) ? 0 : 1);
  res.tab = (block *)bignum_alloc((res.size) * sizeof(block));
  
  int m = k / E, n = k % E;
  if (n == 0) {
    for (i = 0; i < res.size; i++)
      res.tab[i] = a.tab[i+m];
  } else {
    for (i = 0; i < res.size-1; i++) {
      res.tab[i] = a.tab[i+m] >> n;
      res.tab[i] |= ((a.tab[i+m+1] << (E-n)) & MASK);
    }
    res.tab[i] = a.tab[i+m] >> n;
    if (i+m+1 < a.size)
      res.tab[i] |= ((a.tab[i+m+1] << (E-n)) & MASK);
  }

  return res;
}

bignum bignum_add(bignum a, bignum b) {
  if (a.sign == -1 && b.sign == 1) {
    a.sign = 1;
    return bignum_sub(b, a);
  } else if (a.sign == 1 && b.sign == -1) {
    b.sign = 1;
    return bignum_sub(a, b);
  }

  if (b.size > a.size)
    return bignum_add(b, a);

  int i; 
  block carry = 0, tmp;
  bignum sum;

  sum.sign = a.sign;
  sum.tab = (block *)bignum_alloc((a.size + 1) * sizeof(block));
  sum.size = a.size;

  for (i  = 0; i < b.size; i++) {
    tmp = a.tab[i] + b.tab[i] + carry;
    carry = tmp / B;
    sum.tab[i] = tmp % B;
  }
  for (; i < a.size; i++) {
    tmp = a.tab[i] + carry;
    carry = tmp / B;
    sum.tab[i] = tmp % B;
  }

  sum.tab[i] = carry;
  if (carry)
    sum.size++;

  return sum;
}

bignum bignum_sub(bignum a, bignum b) {
  int i, j;
  block tmp, carry;
  bignum diff;
  
  if (a.sign == 1 && b.sign == -1) {
    b.sign = 1;
    return bignum_add(a, b);
  } 
  if (a.sign == -1 && b.sign == 1) {
    b.sign = -1;
    return bignum_add(a, b);
  } 

  if (a.sign == -1 && b.sign == -1) {
    a.sign = b.sign = 1;
    return bignum_sub(b, a);
  } 

  if (a.size < b.size) {
    diff = bignum_sub(b, a);
    diff.sign = -1;
    return diff;
  }

  if (a.size == b.size) {
    for (i = a.size-1; (i >=0) && (a.tab[i] == b.tab[i]); i--);
    if (i == -1) {
      diff.sign = 1;
      diff.size = 1;
      diff.tab = (block *)bignum_alloc(sizeof(block));
      diff.tab[0] = 0;
      return diff;
    }

    diff.size = i + 1;
    diff.tab = (block *)bignum_alloc(diff.size * sizeof(block));
    carry = 0;
    if (a.tab[i] > b.tab[i]) {
      diff.sign = 1;
      for (j = 0; j <= i; j++) {
        tmp = a.tab[j] - b.tab[j] + carry;
        carry = (tmp < 0) ? -1 : 0;
        diff.tab[j] = (tmp + B) % B;
      }
    } else {
      diff.sign = -1;
      for (j = 0; j <= i; j++) {
        tmp = b.tab[j] - a.tab[j] + carry;
        carry = (tmp < 0) ? -1 : 0;
        diff.tab[j] = (tmp + B) % B;
      }
    }
  } else {
    diff.sign = a.sign;
    diff.size = a.size;
    diff.tab = (block *)bignum_alloc((diff.size)*sizeof(block));
    carry = 0;
    for (i = 0; i < b.size; i++) {
      tmp = a.tab[i] - b.tab[i] + carry;
      carry = (tmp < 0) ? -1 : 0;
      diff.tab[i] = (tmp + B) % B;
    }

    for (; i < a.size; i++) {
      tmp = a.tab[i] + carry;
      carry = (tmp < 0) ? -1 : 0;
      diff.tab[i] = (tmp + B) % B;
    }
  }

  for (i = diff.size-1; diff.tab[i] == 0; i--);
  diff.size = i + 1;
  return diff;
}

bignum bignum_mult(bignum a, bignum b) {
  int i, j;
  block tmp, carry;
  bignum prd;

  if (bignum_is_zero(a) || bignum_is_zero(b)) {
    prd.sign = 1;
    prd.size = 1;
    prd.tab = (block *)bignum_alloc(prd.size * sizeof(block));
    prd.tab[0] = 0;
    return prd;
  }

  if (b.size > a.size)
     return bignum_mult(b, a);

  prd.sign = a.sign * b.sign;
  prd.size = a.size + b.size;
  prd.tab = (block *)bignum_alloc((prd.size)*sizeof(block));

  for (i = 0; i < prd.size; i++)
    prd.tab[i] = 0;

  for (i = 0; i < b.size; i++) {
    carry = 0;
    for (j = 0; j < a.size; j++) {
      tmp = b.tab[i] * a.tab[j] + prd.tab[i+j] + carry;
      carry = tmp / B;
      prd.tab[i+j] = tmp % B;
    }
    prd.tab[i+a.size] = carry;
  }

  for (i = prd.size-1; prd.tab[i] == 0; i--);
  prd.size = i + 1;
  return prd;
}

/* slow algorithm */
bignum bignum_rand(int length) {
  int i, j, n;
  bignum ret;

  if (length == 0) {
    ret.sign = 1;
    ret.size = 1;
    ret.tab = (block *)bignum_alloc(sizeof(block));
    ret.tab[0] = 0;
    return ret;
  }

  ret.sign = 1;
  ret.size = length / E;
  if (length % E != 0)
    ret.size++;

  ret.tab = (block *)bignum_alloc(sizeof(block)*ret.size);

  for (i = 0; (i+1) * E < length; i++) {
    ret.tab[i] = rand() % B;
  }

  n = length - i * E;
  ret.tab[i] = ((block)rand()) % B;
  ret.tab[i] |= ((block)0x1 << (n-1));

  for (j = n; j < E; j++)
    ret.tab[i] &= ~((block)0x1 << j);

  return ret;
}

int bignum_length(bignum a) {
  block n = a.tab[a.size-1];
  int len = a.size * E;

  int i;
  for (i = E-1; i > 0; i--)
    if (((n >> i) & 0x1) == 0)
      len--;
    else
      break;

  return len;
}
