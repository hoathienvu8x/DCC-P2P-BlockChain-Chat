#include "rsa.h"

#define rsa_alloc malloc
#define rsa_free free
#define TEST_CNT 80

static int bignum_is_normalized(bignum a) {
  if (a.sign == -1)
    return 0;

  return (a.tab[a.size-1] >> (E-1)) & 0x1; 
}

// a > b > 0, and b is normalized;
static bignum * bignum_normalized_divi(bignum a, bignum b) {
  int i, j, k = a.size, l = b.size;
  bignum q, r;
  block carry, tmp;

  r.sign = 1;
  r.size = a.size;
  r.tab = (block *)rsa_alloc(sizeof(block)*(r.size+1));
  for (i = 0; i < k; i++)
    r.tab[i] = a.tab[i];

  r.tab[k] = 0;

  q.sign = 1;
  q.size = k - l + 1;
  q.tab = (block *)rsa_alloc(sizeof(block)*q.size);
  
  for (i = k-l; i >= 0; i--) {
    q.tab[i] = (r.tab[i+l]*B + r.tab[i+l-1]) / b.tab[l-1];
    if (q.tab[i] >= B)
      q.tab[i] = B-1;

    carry = 0;
    for (j = 0; j < l; j++) {
      tmp = r.tab[i+j] - q.tab[i]*b.tab[j] + carry;
      carry = tmp / B;
      r.tab[i+j] = tmp % B; 
      if (tmp < 0 && r.tab[i+j] != 0) {
        carry -= 1;
        r.tab[i+j] = r.tab[i+j] + B;
      }
    }
    r.tab[i+l] += carry;

    while (r.tab[i+l] < 0) {
      carry = 0;
      for (j = 0; j < l; j++) {
        tmp = r.tab[i+j] + b.tab[j] + carry;
        carry = tmp / B;
        r.tab[i+j] = tmp % B;
      }
      r.tab[i+l] += carry;
      q.tab[i]--;
    }
  }

  for (i = k-l; i >= 1 && q.tab[i] == 0; i--);
  q.size = i+1;

  for (i = l-1; i >= 1 && r.tab[i] == 0; i--);
  r.size = i+1;

  bignum * res = (bignum *)rsa_alloc(sizeof(bignum)*2);
  res[0] = q;
  res[1] = r;
  return res;
}

static bignum bignum_reminder(bignum a, bignum n) {
  int i, cmp;
  bignum r, *quorem, ta, tn, tr;

  cmp = bignum_cmp(a, n);
  if (cmp == -1) {
    bignum_copy(&r, a);
    return r;
  }
  if (cmp == 0) {
    r.sign = r.size = 1;
    r.tab = (block *)rsa_alloc(sizeof(block));
    r.tab[0] = 0;
    return r;
  }

  if (bignum_is_normalized(n)) {
    quorem = bignum_normalized_divi(a, n);
    r = quorem[1];
    rsa_free(quorem[0].tab);
    rsa_free(quorem);

    return r;
  }

  for (i = E-1; i >= 0; i--)
    if ((n.tab[n.size-1] >> i) & 0x1)
      break;

  ta = bignum_lshift(a, E-i-1);
  tn = bignum_lshift(n, E-i-1);
  quorem = bignum_normalized_divi(ta, tn);
  tr = quorem[1];
  r = bignum_rshift(tr, E-i-1);

  rsa_free(quorem[0].tab);
  rsa_free(quorem);
  rsa_free(ta.tab);
  rsa_free(tn.tab);
  rsa_free(tr.tab);

  return r;
}

static bignum bignum_multmod(bignum a, bignum b, bignum n) {
  bignum prd = bignum_mult(a, b);
  bignum res = bignum_reminder(prd, n);

  rsa_free(prd.tab);
  prd.tab = NULL;
  return res;
}

static bignum bignum_expmod(bignum a, bignum b, bignum n) {
  int i, j, start;
  bignum r = bignum_reminder(a, n);
  block *t;

  start = bignum_length(b) % E;
  if (start == 0)
    start = E;

  for (j = start-2; j >= 0; j--) {
    t = r.tab;
    r = bignum_multmod(r, r, n);
    rsa_free(t);

    if (((b.tab[b.size-1] >> j) & 0x1) == 1) {
      t = r.tab;
      r = bignum_multmod(r, a, n);
      rsa_free(t);
    }
  }

  for (i = b.size-2; i >= 0; i--) {
    for (j = E-1; j >= 0; j--) {
      t = r.tab;
      r = bignum_multmod(r, r, n);
      rsa_free(t);

      if (((b.tab[i] >> j) & 0x1) == 1) {
        t = r.tab;
        r = bignum_multmod(r, a, n);
        rsa_free(t);
      }
    }
  }

  return r;
}

static int bignum_miller_rabin(bignum n, int t) {
  bignum two = bignum_from_int(2);
  bignum three = bignum_from_int(3);
  if (bignum_cmp(n, three) == 0 || bignum_cmp(n, two) == 0) {
    rsa_free(two.tab);
    rsa_free(three.tab);
    return 1;
  }

  if (n.tab[0] % 2 == 0)
    return 0;

  int i, j, s = 0, len = bignum_length(n);
  bignum r, a, beta, one, n_minus_one;
  block *bt;

  one = bignum_from_int(1);
  n_minus_one = bignum_sub(n, one);

  for (j = 0; j < n_minus_one.size; j++) {
    if (n_minus_one.tab[j] == 0) {
      s += E;
      continue;
    } else {
      for (i = 0; i < E; i++)
        if (((n_minus_one.tab[j] >> i) & 0x1) == (block)0)
          s++;
        else
          break;
      break;
    }
  }

  r = bignum_rshift(n_minus_one, s);

  while (t--) {
    // TODO: a should be from [2, n-1]
    a = bignum_rand(rand() % len);
    if (bignum_is_one(a) || bignum_is_zero(a)) {
      t++;
      rsa_free(a.tab);
      continue;
    }


    beta = bignum_expmod(a, r, n);
    rsa_free(a.tab);
    a.tab = NULL;


    while(!bignum_is_one(beta) && bignum_cmp(beta, n_minus_one) != 0) {
      j = s - 1;
      while (j-- && bignum_cmp(beta, n_minus_one)!=0) {
        bt = beta.tab;
        beta = bignum_multmod(beta, beta, n);
        rsa_free(bt);
        if (bignum_is_one(beta))
          return 0;
      }

      if (bignum_cmp(beta, n_minus_one) != 0)
        return 0;
    }
  }

  rsa_free(r.tab);
  rsa_free(one.tab);
  rsa_free(n_minus_one.tab);

  return 1;
}

static bignum bignum_rand_prime(int length) {
  bignum p = bignum_rand(length);

  while (!bignum_miller_rabin(p, TEST_CNT)) {
    rsa_free(p.tab);
    p.tab = NULL;
    p = bignum_rand(length);
  }

  return p;
}

static bignum bignum_gcd(bignum a, bignum b) {
  bignum res;
  bignum tmp;
  res.sign = 1;

  if (bignum_is_zero(b)) {
    res.tab = (block *)rsa_alloc((res.size) * sizeof(block));
    bignum_copy(&res, a);
    return res;
  }
  if (bignum_is_zero(a)) {
    res.tab = (block *)rsa_alloc((res.size) * sizeof(block));
    bignum_copy(&res, b);
    return res;
  }

  if (bignum_cmp(a, b)) {
    tmp = bignum_reminder(a, b);
    res = bignum_gcd(b, tmp);
    rsa_free(tmp.tab);
    return res;
  } else {
    tmp = bignum_reminder(b, a);
    res = bignum_gcd(a, tmp);
    rsa_free(tmp.tab);
    return res;
  }
}

static bignum bignum_divi(bignum a, bignum n) {
  int i, cmp;
  bignum q, ta, tn, *quorem;

  cmp = bignum_cmp(a, n);
  if (cmp == -1) {
    q.sign = q.size = 1;
    q.tab = (block *)rsa_alloc(sizeof(block));
    q.tab[0] = 0;
    return q;
  }
  if (cmp == 0) {
    q.sign = q.size = 1;
    q.tab = (block *)rsa_alloc(sizeof(block));
    q.tab[0] = 1;
    return q;
  }

  if (bignum_is_normalized(n)) {
    quorem = bignum_normalized_divi(a, n);
    q = quorem[0];
    rsa_free(quorem[1].tab);
    rsa_free(quorem);
    return q;
  }

  for (i = E-1; i >= 0; i--)
    if ((n.tab[n.size-1] >> i) & 0x1)
      break;

  ta = bignum_lshift(a, E-i-1);
  tn = bignum_lshift(n, E-i-1);
  quorem = bignum_normalized_divi(ta, tn);
  q = quorem[0];

  rsa_free(quorem[1].tab);
  rsa_free(quorem);
  rsa_free(ta.tab);
  rsa_free(tn.tab);
  return q;
}

static bignum bignum_inverse(bignum a, bignum n) {
  int mark = 0, mark1 = 1;
  bignum r[2], v[2], q;
  block *t;

  r[0] = bignum_reminder(n, a);
  bignum_copy(&r[1], a);
  q = bignum_divi(n, a);
  
  v[1] = bignum_from_int(1);
 
  bignum_copy(&v[0], q);
  rsa_free(q.tab);
  if (!bignum_is_zero(v[0]))
      v[0].sign *= -1;

  bignum tmp0, tmp1;
  while (!bignum_is_zero(r[mark])) {
    mark ^= 1;
    mark1 ^= 1;

    q = bignum_divi(r[mark], r[mark1]);

    t = r[mark].tab;
    r[mark] = bignum_reminder(r[mark], r[mark1]); 
    rsa_free(t);

    tmp0 = bignum_mult(q, v[mark1]);
    tmp1 = bignum_sub(v[mark], tmp0);

    rsa_free(v[mark].tab);
    v[mark] = bignum_reminder(tmp1, n);

    rsa_free(q.tab);
    rsa_free(tmp0.tab);
    rsa_free(tmp1.tab);
  }

  tmp0 = bignum_add(v[mark^1], n);
  bignum res = bignum_reminder(tmp0, n);

  rsa_free(tmp0.tab);
  rsa_free(v[0].tab);
  rsa_free(v[1].tab);
  rsa_free(r[0].tab);
  rsa_free(r[1].tab);

  return res;
}
// https://github.com/ansal10/BigInteger/blob/master/Big2.c
void rsa_keygen(bignum * n, bignum * e, bignum * d, int len) {
  bignum p, q, phi_n;
  bignum t0, t1, gcd, tmp;
  bignum ONE = bignum_from_int(1);

  p = bignum_rand_prime(len);
  q = bignum_rand_prime(len);

  while (bignum_cmp(p, q) == 0) {
    rsa_free(q.tab);
    q = bignum_rand_prime(len);
  }
  *n = bignum_mult(p, q);
  t0 = bignum_sub(p, ONE);
  t1 = bignum_sub(q, ONE);
  phi_n = bignum_mult(t0, t1);
  rsa_free(t0.tab);
  rsa_free(t1.tab);
  
  tmp = bignum_rand_prime(len);
  *e = bignum_reminder(tmp, phi_n);

  while (1) {
    gcd = bignum_gcd(*e, phi_n);
    if (bignum_cmp(gcd, ONE) == 0) {
      rsa_free(gcd.tab);

      *d = bignum_inverse(*e, phi_n);
      break;
    }

    int e_len;
    do {
      e_len = rand() % (bignum_length(*n));
    } while (e_len <= 1);

    do {
      rsa_free(e->tab);
      tmp = bignum_rand_prime(len);
      *e = bignum_reminder(tmp, phi_n);
    } while (bignum_is_zero(*e) || bignum_is_one(*e));
  }

  rsa_free(ONE.tab);
  rsa_free(p.tab);
  rsa_free(q.tab);
  rsa_free(phi_n.tab);
}

bignum rsa_encrypt(bignum m, bignum e, bignum n) {
  return bignum_expmod(m, e, n);
}

bignum rsa_decrypt(bignum c, bignum d, bignum n) {
  return bignum_expmod(c, d, n);
}
