
#include <xen/ctype.h>
#include <xen/lib.h>


/* for inc/ctype.h */
unsigned char _ctype[] = {
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 0-7 */
_C,_C|_S,_C|_S,_C|_S,_C|_S,_C|_S,_C,_C,         /* 8-15 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 16-23 */
_C,_C,_C,_C,_C,_C,_C,_C,                        /* 24-31 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,                    /* 32-39 */
_P,_P,_P,_P,_P,_P,_P,_P,                        /* 40-47 */
_D,_D,_D,_D,_D,_D,_D,_D,                        /* 48-55 */
_D,_D,_P,_P,_P,_P,_P,_P,                        /* 56-63 */
_P,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U|_X,_U,      /* 64-71 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 72-79 */
_U,_U,_U,_U,_U,_U,_U,_U,                        /* 80-87 */
_U,_U,_U,_P,_P,_P,_P,_P,                        /* 88-95 */
_P,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L|_X,_L,      /* 96-103 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 104-111 */
_L,_L,_L,_L,_L,_L,_L,_L,                        /* 112-119 */
_L,_L,_L,_P,_P,_P,_P,_C,                        /* 120-127 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 128-143 */
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                /* 144-159 */
_S|_SP,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,   /* 160-175 */
_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,_P,       /* 176-191 */
_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,_U,       /* 192-207 */
_U,_U,_U,_U,_U,_U,_U,_P,_U,_U,_U,_U,_U,_U,_U,_L,       /* 208-223 */
_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,_L,       /* 224-239 */
_L,_L,_L,_L,_L,_L,_L,_P,_L,_L,_L,_L,_L,_L,_L,_L};      /* 240-255 */


unsigned long str_to_quad(unsigned char *s)
{
    unsigned long quad = 0;
    do {
        quad <<= 8;
        quad  |= simple_strtol(s, (char **)&s, 10);
    }  
    while ( *s++ == '.' );
    return quad;
}


unsigned char *quad_to_str(unsigned long q, unsigned char *s)
{
    sprintf(s, "%ld.%ld.%ld.%ld", 
            (q>>24)&255, (q>>16)&255, (q>>8)&255, (q>>0)&255);
    return s;
}
   

/* a couple of 64 bit operations ported from freebsd */

/*-
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/libkern/divdi3.c,v 1.6 1999/08/28 00:46:31 peter Exp $
 */

#include <asm/types.h>

#if BITS_PER_LONG == 32

/*
 * Depending on the desired operation, we view a `long long' (aka quad_t) in
 * one or more of the following formats.
 */
union uu {
        s64            q;              /* as a (signed) quad */
        s64            uq;             /* as an unsigned quad */
        long           sl[2];          /* as two signed longs */
        unsigned long  ul[2];          /* as two unsigned longs */
};
/* XXX RN: Yuck hardcoded endianess :) */
#define _QUAD_HIGHWORD 1
#define _QUAD_LOWWORD 0
/*
 * Define high and low longwords.
 */
#define H               _QUAD_HIGHWORD
#define L               _QUAD_LOWWORD

/*
 * Total number of bits in a quad_t and in the pieces that make it up.
 * These are used for shifting, and also below for halfword extraction
 * and assembly.
 */
#define CHAR_BIT        8               /* number of bits in a char */
#define QUAD_BITS       (sizeof(s64) * CHAR_BIT)
#define LONG_BITS       (sizeof(long) * CHAR_BIT)
#define HALF_BITS       (sizeof(long) * CHAR_BIT / 2)

/*
 * Extract high and low shortwords from longword, and move low shortword of
 * longword to upper half of long, i.e., produce the upper longword of
 * ((quad_t)(x) << (number_of_bits_in_long/2)).  (`x' must actually be u_long.)
 *
 * These are used in the multiply code, to split a longword into upper
 * and lower halves, and to reassemble a product as a quad_t, shifted left
 * (sizeof(long)*CHAR_BIT/2).
 */
#define HHALF(x)        ((x) >> HALF_BITS)
#define LHALF(x)        ((x) & ((1 << HALF_BITS) - 1))
#define LHUP(x)         ((x) << HALF_BITS)

/*
 * Multiprecision divide.  This algorithm is from Knuth vol. 2 (2nd ed),
 * section 4.3.1, pp. 257--259.
 */
#define	B	(1 << HALF_BITS)	/* digit base */

/* Combine two `digits' to make a single two-digit number. */
#define	COMBINE(a, b) (((u_long)(a) << HALF_BITS) | (b))

/* select a type for digits in base B: use unsigned short if they fit */
#if ULONG_MAX == 0xffffffff && USHRT_MAX >= 0xffff
typedef unsigned short digit;
#else
typedef u_long digit;
#endif

/*
 * Shift p[0]..p[len] left `sh' bits, ignoring any bits that
 * `fall out' the left (there never will be any such anyway).
 * We may assume len >= 0.  NOTE THAT THIS WRITES len+1 DIGITS.
 */
static void
shl(register digit *p, register int len, register int sh)
{
	register int i;

	for (i = 0; i < len; i++)
		p[i] = LHALF(p[i] << sh) | (p[i + 1] >> (HALF_BITS - sh));
	p[i] = LHALF(p[i] << sh);
}

/*
 * __qdivrem(u, v, rem) returns u/v and, optionally, sets *rem to u%v.
 *
 * We do this in base 2-sup-HALF_BITS, so that all intermediate products
 * fit within u_long.  As a consequence, the maximum length dividend and
 * divisor are 4 `digits' in this base (they are shorter if they have
 * leading zeros).
 */
u64
__qdivrem(uq, vq, arq)
	u64 uq, vq, *arq;
{
	union uu tmp;
	digit *u, *v, *q;
	register digit v1, v2;
	u_long qhat, rhat, t;
	int m, n, d, j, i;
	digit uspace[5], vspace[5], qspace[5];

	/*
	 * Take care of special cases: divide by zero, and u < v.
	 */
	if (vq == 0) {
		/* divide by zero. */
		static volatile const unsigned int zero = 0;

		tmp.ul[H] = tmp.ul[L] = 1 / zero;
		if (arq)
			*arq = uq;
		return (tmp.q);
	}
	if (uq < vq) {
		if (arq)
			*arq = uq;
		return (0);
	}
	u = &uspace[0];
	v = &vspace[0];
	q = &qspace[0];

	/*
	 * Break dividend and divisor into digits in base B, then
	 * count leading zeros to determine m and n.  When done, we
	 * will have:
	 *	u = (u[1]u[2]...u[m+n]) sub B
	 *	v = (v[1]v[2]...v[n]) sub B
	 *	v[1] != 0
	 *	1 < n <= 4 (if n = 1, we use a different division algorithm)
	 *	m >= 0 (otherwise u < v, which we already checked)
	 *	m + n = 4
	 * and thus
	 *	m = 4 - n <= 2
	 */
	tmp.uq = uq;
	u[0] = 0;
	u[1] = HHALF(tmp.ul[H]);
	u[2] = LHALF(tmp.ul[H]);
	u[3] = HHALF(tmp.ul[L]);
	u[4] = LHALF(tmp.ul[L]);
	tmp.uq = vq;
	v[1] = HHALF(tmp.ul[H]);
	v[2] = LHALF(tmp.ul[H]);
	v[3] = HHALF(tmp.ul[L]);
	v[4] = LHALF(tmp.ul[L]);
	for (n = 4; v[1] == 0; v++) {
		if (--n == 1) {
			u_long rbj;	/* r*B+u[j] (not root boy jim) */
			digit q1, q2, q3, q4;

			/*
			 * Change of plan, per exercise 16.
			 *	r = 0;
			 *	for j = 1..4:
			 *		q[j] = floor((r*B + u[j]) / v),
			 *		r = (r*B + u[j]) % v;
			 * We unroll this completely here.
			 */
			t = v[2];	/* nonzero, by definition */
			q1 = u[1] / t;
			rbj = COMBINE(u[1] % t, u[2]);
			q2 = rbj / t;
			rbj = COMBINE(rbj % t, u[3]);
			q3 = rbj / t;
			rbj = COMBINE(rbj % t, u[4]);
			q4 = rbj / t;
			if (arq)
				*arq = rbj % t;
			tmp.ul[H] = COMBINE(q1, q2);
			tmp.ul[L] = COMBINE(q3, q4);
			return (tmp.q);
		}
	}

	/*
	 * By adjusting q once we determine m, we can guarantee that
	 * there is a complete four-digit quotient at &qspace[1] when
	 * we finally stop.
	 */
	for (m = 4 - n; u[1] == 0; u++)
		m--;
	for (i = 4 - m; --i >= 0;)
		q[i] = 0;
	q += 4 - m;

	/*
	 * Here we run Program D, translated from MIX to C and acquiring
	 * a few minor changes.
	 *
	 * D1: choose multiplier 1 << d to ensure v[1] >= B/2.
	 */
	d = 0;
	for (t = v[1]; t < B / 2; t <<= 1)
		d++;
	if (d > 0) {
		shl(&u[0], m + n, d);		/* u <<= d */
		shl(&v[1], n - 1, d);		/* v <<= d */
	}
	/*
	 * D2: j = 0.
	 */
	j = 0;
	v1 = v[1];	/* for D3 -- note that v[1..n] are constant */
	v2 = v[2];	/* for D3 */
	do {
		register digit uj0, uj1, uj2;

		/*
		 * D3: Calculate qhat (\^q, in TeX notation).
		 * Let qhat = min((u[j]*B + u[j+1])/v[1], B-1), and
		 * let rhat = (u[j]*B + u[j+1]) mod v[1].
		 * While rhat < B and v[2]*qhat > rhat*B+u[j+2],
		 * decrement qhat and increase rhat correspondingly.
		 * Note that if rhat >= B, v[2]*qhat < rhat*B.
		 */
		uj0 = u[j + 0];	/* for D3 only -- note that u[j+...] change */
		uj1 = u[j + 1];	/* for D3 only */
		uj2 = u[j + 2];	/* for D3 only */
		if (uj0 == v1) {
			qhat = B;
			rhat = uj1;
			goto qhat_too_big;
		} else {
			u_long nn = COMBINE(uj0, uj1);
			qhat = nn / v1;
			rhat = nn % v1;
		}
		while (v2 * qhat > COMBINE(rhat, uj2)) {
	qhat_too_big:
			qhat--;
			if ((rhat += v1) >= B)
				break;
		}
		/*
		 * D4: Multiply and subtract.
		 * The variable `t' holds any borrows across the loop.
		 * We split this up so that we do not require v[0] = 0,
		 * and to eliminate a final special case.
		 */
		for (t = 0, i = n; i > 0; i--) {
			t = u[i + j] - v[i] * qhat - t;
			u[i + j] = LHALF(t);
			t = (B - HHALF(t)) & (B - 1);
		}
		t = u[j] - t;
		u[j] = LHALF(t);
		/*
		 * D5: test remainder.
		 * There is a borrow if and only if HHALF(t) is nonzero;
		 * in that (rare) case, qhat was too large (by exactly 1).
		 * Fix it by adding v[1..n] to u[j..j+n].
		 */
		if (HHALF(t)) {
			qhat--;
			for (t = 0, i = n; i > 0; i--) { /* D6: add back. */
				t += u[i + j] + v[i];
				u[i + j] = LHALF(t);
				t = HHALF(t);
			}
			u[j] = LHALF(u[j] + t);
		}
		q[j] = qhat;
	} while (++j <= m);		/* D7: loop on j. */

	/*
	 * If caller wants the remainder, we have to calculate it as
	 * u[m..m+n] >> d (this is at most n digits and thus fits in
	 * u[m+1..m+n], but we may need more source digits).
	 */
	if (arq) {
		if (d) {
			for (i = m + n; i > m; --i)
				u[i] = (u[i] >> d) |
				    LHALF(u[i - 1] << (HALF_BITS - d));
			u[i] = 0;
		}
		tmp.ul[H] = COMBINE(uspace[1], uspace[2]);
		tmp.ul[L] = COMBINE(uspace[3], uspace[4]);
		*arq = tmp.q;
	}

	tmp.ul[H] = COMBINE(qspace[1], qspace[2]);
	tmp.ul[L] = COMBINE(qspace[3], qspace[4]);
	return (tmp.q);
}


/*
 * Divide two signed quads.
 * ??? if -1/2 should produce -1 on this machine, this code is wrong
 */
s64
__divdi3(s64 a, s64 b)
{
	u64 ua, ub, uq;
	int neg;

	if (a < 0)
		ua = -(u64)a, neg = 1;
	else
		ua = a, neg = 0;
	if (b < 0)
		ub = -(u64)b, neg ^= 1;
	else
		ub = b;
	uq = __qdivrem(ua, ub, (u64 *)0);
	return (neg ? -uq : uq);
}

/*
 * Divide two unsigned quads.
 */
u64
__udivdi3(a, b)
        u64 a, b;
{

        return (__qdivrem(a, b, (u64 *)0));
}

#endif /* BITS_PER_LONG == 32 */


/* HASH/RANDOMISATION FUNCTION
 * Based on lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * You can use this free for any purpose.  It has no warranty.
 * See http://burlteburtle.net/bob/hash/evahash.html 
 */

#define mix(a,b,c)                                      \
    do {                                                \
        a -= b; a -= c; a ^= (c>>13);                   \
        b -= c; b -= a; b ^= (a<< 8);                   \
        c -= a; c -= b; c ^= ((b&0xffffffff)>>13);      \
        a -= b; a -= c; a ^= ((c&0xffffffff)>>12);      \
        b -= c; b -= a; b = (b ^ (a<<16)) & 0xffffffff; \
        c -= a; c -= b; c = (c ^ (b>> 5)) & 0xffffffff; \
        a -= b; a -= c; a = (a ^ (c>> 3)) & 0xffffffff; \
        b -= c; b -= a; b = (b ^ (a<<10)) & 0xffffffff; \
        c -= a; c -= b; c = (c ^ (b>>15)) & 0xffffffff; \
    } while ( 0 )

u32 hash(unsigned char *k, unsigned long len)
{
    u32 a, b, c, l;

    l = len;
    a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
    c = 0xa5a5a5a5;      /* another arbitrary value (KAF, 13/5/03) */

    while ( l >= 12 )
    {
        a += (k[0] + ((u32)k[1]<<8) + ((u32)k[2]<<16)  + ((u32)k[3]<<24));
        b += (k[4] + ((u32)k[5]<<8) + ((u32)k[6]<<16)  + ((u32)k[7]<<24));
        c += (k[8] + ((u32)k[9]<<8) + ((u32)k[10]<<16) + ((u32)k[11]<<24));
        mix(a,b,c);
        k += 12; l -= 12;
    }

    c += len;
    switch ( l )
    {
    case 11: c+=((u32)k[10]<<24);
    case 10: c+=((u32)k[9]<<16);
    case 9 : c+=((u32)k[8]<<8);
        /* the first byte of c is reserved for the length */
    case 8 : b+=((u32)k[7]<<24);
    case 7 : b+=((u32)k[6]<<16);
    case 6 : b+=((u32)k[5]<<8);
    case 5 : b+=k[4];
    case 4 : a+=((u32)k[3]<<24);
    case 3 : a+=((u32)k[2]<<16);
    case 2 : a+=((u32)k[1]<<8);
    case 1 : a+=k[0];
        /* case 0: nothing left to add */
    }

    mix(a,b,c);

    return c;
}
