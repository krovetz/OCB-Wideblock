/*------------------------------------------------------------------------
/ OCB (RFC 7523) Reference Code (Unoptimized C)   Last modified 7-JUL-2017
/-------------------------------------------------------------------------
/ Copyright (c) 2013, 2017 Ted Krovetz.
/
/ Permission to use, copy, modify, and/or distribute this software for any
/ purpose with or without fee is hereby granted, provided that the above
/ copyright notice and this permission notice appear in all copies.
/
/ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
/ WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
/ MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
/ ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
/ WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
/ ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
/ OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/
/ Phillip Rogaway holds patents relevant to OCB. See the following for
/ his free patent grant: http://www.cs.ucdavis.edu/~rogaway/ocb/grant.htm
/
/ Comments are welcome: Ted Krovetz <ted@krovetz.net>
/------------------------------------------------------------------------- */

/* This implementation is not optimized and is suceptible to timing attack.
/  It mirrors the OCB RFC to aid in understanding and should not be used
/  for any other purpose. This implementation manipulates data as bytes
/  rather than machine words, which avoids endian issues entirely.         */

#include <string.h>

#define BLOCKBYTES      200 /* Must be compatible with blockcipher in use */
#define KEYBYTES        16 /* Must be compatible with blockcipher in use */

#define NONCEBYTES      2   /* Max BLOCKBYTES - (BLOCKBYTES <= 16 ? 1 : 2)  */
#define TAGBYTES        32  /* Must be <= min(BLOCKBYTES,32)                */

#if BLOCKBYTES == 4
#define RESIDUE         141
#define SHIFT           17
#define MASKLEN         4
#elif BLOCKBYTES == 8
#define RESIDUE         27
#define SHIFT           25
#define MASKLEN         5
#elif BLOCKBYTES == 12
#define RESIDUE         1601
#define SHIFT           33
#define MASKLEN         6
#elif BLOCKBYTES == 16
#define RESIDUE         135
#define SHIFT           8
#define MASKLEN         6
#elif BLOCKBYTES == 24
#define RESIDUE         135
#define SHIFT           40
#define MASKLEN         7
#elif BLOCKBYTES == 32
#define RESIDUE         1061
#define SHIFT           1
#define MASKLEN         8
#elif BLOCKBYTES == 48
#define RESIDUE         4109
#define SHIFT           80
#define MASKLEN         8
#elif BLOCKBYTES == 64
#define RESIDUE         293
#define SHIFT           176
#define MASKLEN         8
#elif BLOCKBYTES == 96
#define RESIDUE         655377
#define SHIFT           160
#define MASKLEN         9
#elif BLOCKBYTES == 128
#define RESIDUE         524355
#define SHIFT           352
#define MASKLEN         9
#elif BLOCKBYTES == 200
#define RESIDUE         18435
#define SHIFT           192
#define MASKLEN         10
#else
#error -- Unimplemented blocklength
#endif

typedef unsigned char block[BLOCKBYTES];

/* ------------------------------------------------------------------------- */
/* These two examples show how to integrate a block cipher into this code.   */

#define OPENSSL_AES     0  /* Requires: BLOCKBYTES==16, KEYBYTES==16/24/32  */
#define RFC_VECTORS 1      /* Uses RC6 as specified in RFC????              */

#if OPENSSL_AES

#include <openssl/aes.h>
static void encipher(block c, block p, unsigned char key[KEYBYTES]) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, KEYBYTES * 8, &aes_key);
    AES_encrypt(p, c, &aes_key);
}
static void decipher(block p, block c, unsigned char key[KEYBYTES]) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, KEYBYTES * 8, &aes_key);
    AES_decrypt(p, c, &aes_key);
}

#elif RFC_VECTORS

#include "rc6.h"  /* https://github.com/krovetz/RC6-RC5-Wideblock */
#define RC6_RNDS 16

static void encipher(block c, block p, unsigned char key[KEYBYTES]) {
    unsigned char rkey[(2*RC6_RNDS+4)*BLOCKBYTES];
    rc6_setup(rkey, BLOCKBYTES*8/4, RC6_RNDS, KEYBYTES, key);
    rc6_encrypt(rkey, BLOCKBYTES*8/4, RC6_RNDS, p, c);
}
static void decipher(block p, block c, unsigned char key[KEYBYTES]) {
    unsigned char rkey[(2*RC6_RNDS+4)*BLOCKBYTES];
    rc6_setup(rkey, BLOCKBYTES*8/4, RC6_RNDS, KEYBYTES, key);
    rc6_decrypt(rkey, BLOCKBYTES*8/4, RC6_RNDS, c, p);
}

#endif

#include <stdio.h>

/* set vectors non-zero to print intermediate setup/encrypt values */
int ocb_vectors = 0;

/* pbuf is used to print sequences of bytes from in memory         */
static void pbuf_if(const void *p, int len, const void *s)
{
    if (ocb_vectors) {
        int i;
        if (s) printf("%s", (char *)s);
        for (i=0; i<len; i++) printf("%02X", ((unsigned char *)p)[i]);
        printf("\n");
    }
}

/* ------------------------------------------------------------------------- */

static void xor_block(block d, block s1, block s2) {
    int i;
    for (i=0; i<BLOCKBYTES; i++)
        d[i] = s1[i] ^ s2[i];
}

/* ------------------------------------------------------------------------- */

static void double_block(block d, block s) {
    int i;
    unsigned char tmp = s[0];
    for (i=0; i<BLOCKBYTES-1; i++)
        d[i] = (s[i] << 1) | (s[i+1] >> 7);
    d[BLOCKBYTES-1] = s[BLOCKBYTES-1] << 1;
    if (tmp >> 7) {
        d[BLOCKBYTES-1] ^= (unsigned char)(RESIDUE >> 0);
        d[BLOCKBYTES-2] ^= (unsigned char)(RESIDUE >> 8);
        d[BLOCKBYTES-3] ^= (unsigned char)(RESIDUE >> 16);
    }
}

/* ------------------------------------------------------------------------- */

static void calc_L_i(block l, block ldollar, int i) {
    double_block(l, ldollar);         /* l is now L_0               */
    for ( ; (i&1)==0 ; i>>=1)
        double_block(l,l);            /* double for each trailing 0 */
}

/* ------------------------------------------------------------------------- */

static void hash(block result, unsigned char *k,
                 unsigned char *a, int abytes) {
    block lstar, ldollar, offset, sum, tmp;
    int i;
    
    if (ocb_vectors) printf("\n  Assignments during HASH(K,A)\n\n");

    /* Key-dependent variables */
    
    /* L_* = ENCIPHER(K, zeros(BLOCKLEN)) */
    memset(tmp, 0, BLOCKBYTES);
    encipher(lstar, tmp, k);
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar); 

    pbuf_if(lstar, BLOCKBYTES, "  L_*: ");
    pbuf_if(ldollar, BLOCKBYTES, "  L_$: "); 
    
    /* Process any whole blocks */
    
    /* Sum_0 = zeros(BLOCKLEN) */
    memset(sum, 0, BLOCKBYTES);
    /* Offset_0 = zeros(BLOCKLEN) */
    memset(offset, 0, BLOCKBYTES);
    for (i=1; i<=abytes/BLOCKBYTES; i++) {
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        if (ocb_vectors) printf("i=%d\n", i);
        pbuf_if(tmp, BLOCKBYTES, "  L_{ntz(i)}: ");
        xor_block(offset, offset, tmp);
        /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i) */
        pbuf_if(offset, BLOCKBYTES, "  Offset_i: ");
        xor_block(tmp, offset, a);
        encipher(tmp, tmp, k);
        xor_block(sum, sum, tmp);
        pbuf_if(sum, BLOCKBYTES, "  Sum_i: ");
        a = a + BLOCKBYTES;
    }

    /* Process any final partial block; compute final hash value */

    abytes = abytes % BLOCKBYTES;  /* Bytes in final block */
    if (abytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        pbuf_if(offset, BLOCKBYTES, "  Offset_*: ");
        /* CipherInput = (A_* || 1 || Zerofill) xor Offset_* */
        memset(tmp, 0, BLOCKBYTES);
        memcpy(tmp, a, abytes);
        tmp[abytes] = 0x80;
        xor_block(tmp, offset, tmp);
        pbuf_if(tmp, BLOCKBYTES, "  CipherInput: ");
       /* Sum = Sum_m xor ENCIPHER(K, CipherInput) */
        encipher(tmp, tmp, k);
        xor_block(sum, tmp, sum);
    }
    pbuf_if(sum, BLOCKBYTES, "  Sum: ");
    
    memcpy(result, sum, BLOCKBYTES);
}

/* ------------------------------------------------------------------------- */

static int ocb_crypt(unsigned char *out, unsigned char *k, unsigned char *n,
                     unsigned char *a, unsigned abytes,
                     unsigned char *in, unsigned inbytes, int encrypting) {
    block lstar, ldollar, sum, offset, ktop, pad, nonce, tag, tmp, ad_hash;
    unsigned char stretch[BLOCKBYTES * 3];
    unsigned bottom, tagrep, byteshift, bitshift, i;

    /* Hash associated data */
    hash(ad_hash, k, a, abytes);

    if (ocb_vectors) printf("\n  Assignments during OCB-ENCRYPT\n\n");
    
    /* Strip ciphertext of its tag */
    if ( ! encrypting ) {
         if (inbytes < TAGBYTES) return -1;
         inbytes -= TAGBYTES;
    }
     
    /* Key-dependent variables */

    /* L_* = ENCIPHER(K, zeros(BLOCKLEN)) */
    memset(tmp, 0, BLOCKBYTES);
    encipher(lstar, tmp, k);
    pbuf_if(lstar, BLOCKBYTES, "  L_*: ");
    /* L_$ = double(L_*) */
    double_block(ldollar, lstar);
    pbuf_if(ldollar, BLOCKBYTES, "  L_$: "); 

    /* tagrep = min(8, t), t is smallest integer so that 2^t >= BLOCKLEN */
    for (tagrep=0, i=BLOCKBYTES*8-1; i>0 && tagrep<8; tagrep++, i >>= 1)
        ;

    /* Nonce-dependent and per-encryption variables */

    /* Nonce = num2str(TAGLEN mod BLOCKLEN,tagrep) || Zerofill || 1 || N */
    memset(nonce,0,BLOCKBYTES);
    memcpy(&nonce[BLOCKBYTES-NONCEBYTES],n,NONCEBYTES);
    nonce[0] = (unsigned char)((TAGBYTES%BLOCKBYTES * 8) << (8-tagrep));
    nonce[BLOCKBYTES-NONCEBYTES-1] |= 0x01;
    pbuf_if(nonce, BLOCKBYTES, "  Nonce: "); 
    /* bottom = str2num(Nonce[BLOCKLEN-MASKLEN+1..BLOCKLEN]) */
    bottom = ((nonce[BLOCKBYTES-2] << 8) | nonce[BLOCKBYTES-1]) &
             ((1 << MASKLEN) - 1);
    if (ocb_vectors) printf("  bottom: %d\n", bottom);
    /* Ktop = ENCIPHER(K, Nonce[1..BLOCKLEN-MASKLEN] || zeros(MASKLEN)) */
    nonce[BLOCKBYTES-1] ^= bottom;       /* Zero nonce at each bottom bit */
    nonce[BLOCKBYTES-2] ^= (bottom >> 8);
    encipher(ktop, nonce, k);
    pbuf_if(ktop, BLOCKBYTES, "  Ktop: "); 
    /* ShiftedKtop = Ktop[1..BLOCKLEN-SHIFT] xor Ktop[1+SHIFT..BLOCKLEN]
       Stretch = Ktop || ShiftedKtop */
    byteshift = SHIFT/8;
    bitshift  = SHIFT%8;
    memcpy(stretch, ktop, BLOCKBYTES);
    memcpy(stretch + BLOCKBYTES, ktop, BLOCKBYTES);
    memset(stretch + 2*BLOCKBYTES, 0, BLOCKBYTES);
    for (i=BLOCKBYTES; i<2*BLOCKBYTES; i++)
        stretch[i] ^= (stretch[i+byteshift]<<bitshift) |
                      (stretch[i+byteshift+1]>>(8-bitshift));
    pbuf_if(stretch, 2 * BLOCKBYTES, "  Stretch: "); 
    /* Offset_0 = Stretch[1+bottom..BLOCKLEN+bottom] */
    byteshift = bottom/8;
    bitshift  = bottom%8;
    for (i=0; i<BLOCKBYTES; i++)
        offset[i] = (stretch[i+byteshift] << bitshift) |
                    (stretch[i+byteshift+1] >> (8-bitshift));
    pbuf_if(offset, BLOCKBYTES, "  Offset_0: "); 
    /* Checksum_0 = zeros(BLOCKLEN) */
    memset(sum, 0, BLOCKBYTES);

    /* Process any whole blocks */

    for (i=1; i<=inbytes/BLOCKBYTES; i++) {
        if (ocb_vectors) printf("i=%d\n", i);
        /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
        calc_L_i(tmp, ldollar, i);
        pbuf_if(tmp, BLOCKBYTES, "  L_{ntz(i)}: "); 
        xor_block(offset, offset, tmp);
        pbuf_if(offset, BLOCKBYTES, "  Offset_i: ");
       
        xor_block(tmp, offset, in);
        if (encrypting) {
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, in, sum);
            pbuf_if(sum, BLOCKBYTES, "  Checksum_i: ");
            /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) */
            encipher(tmp, tmp, k);
            xor_block(out, offset, tmp);
            pbuf_if(out, BLOCKBYTES, "  C_i: ");
        } else {
            /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
            decipher(tmp, tmp, k);
            xor_block(out, offset, tmp);
            /* Checksum_i = Checksum_{i-1} xor P_i */
            xor_block(sum, out, sum);
        }
        in += BLOCKBYTES;
        out += BLOCKBYTES;
    }

    /* Process any final partial block and compute raw tag */

    inbytes = inbytes % BLOCKBYTES;  /* Bytes in final block */
    if (inbytes > 0) {
        /* Offset_* = Offset_m xor L_* */
        xor_block(offset, offset, lstar);
        pbuf_if(offset, BLOCKBYTES, "  Offset_*: ");
        /* Pad = ENCIPHER(K, Offset_*) */
        encipher(pad, offset, k);
        pbuf_if(pad, BLOCKBYTES, "  Pad: ");
        
        if (encrypting) {
            /* Checksum_* = Checksum_m xor PaddedP */
            memset(tmp, 0, BLOCKBYTES);
            memcpy(tmp, in, inbytes);
            tmp[inbytes] = 0x80;
            pbuf_if(tmp, BLOCKBYTES, "  PaddedP: "); 
            xor_block(sum, tmp, sum);
            pbuf_if(sum, BLOCKBYTES, "  Checksum_*: "); 
            /* C_* = P_* xor Pad[1..bitlen(P_*)] */
            xor_block(pad, tmp, pad);
            memcpy(out, pad, inbytes);
            pbuf_if(out, inbytes, "  C_*: "); 
            out = out + inbytes;
        } else {
            /* P_* = C_* xor Pad[1..bitlen(C_*)] */
            memcpy(tmp, pad, BLOCKBYTES);
            memcpy(tmp, in, inbytes);
            xor_block(tmp, pad, tmp);
            tmp[inbytes] = 0x80;
            memcpy(out, tmp, inbytes);
            /* Checksum_* = Checksum_m xor PaddedP */
            xor_block(sum, tmp, sum);
            in = in + inbytes;
        }
    }
    
    /* Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A) */
    xor_block(tmp, sum, offset);
    xor_block(tmp, tmp, ldollar);
    encipher(tag, tmp, k);
    xor_block(tag, ad_hash, tag);
    pbuf_if(tag, BLOCKBYTES, "  Tag: "); 
    
    if (encrypting) {
        memcpy(out, tag, TAGBYTES);
        return 0;
    } else
        return (memcmp(in,tag,TAGBYTES) ? -1 : 0);     /* Check for validity */
}

/* ------------------------------------------------------------------------- */

#define OCB_ENCRYPT 1
#define OCB_DECRYPT 0

void ocb_encrypt(unsigned char *c, unsigned char *k, unsigned char *n,
                 unsigned char *a, unsigned abytes,
                 unsigned char *p, unsigned pbytes) {
    ocb_crypt(c, k, n, a, abytes, p, pbytes, OCB_ENCRYPT);
}

/* ------------------------------------------------------------------------- */

int ocb_decrypt(unsigned char *p, unsigned char *k, unsigned char *n,
                unsigned char *a, unsigned abytes,
                unsigned char *c, unsigned cbytes) {
    return ocb_crypt(p, k, n, a, abytes, c, cbytes, OCB_DECRYPT);
}

/* ------------------------------------------------------------------------- */

/* Test against RFC's vectors */

#include <stdio.h>
#include <stdlib.h>

static void pvec(unsigned char kc, unsigned kstep,
                 unsigned char pc, unsigned pbytes, unsigned pstep,
                 unsigned char ac, unsigned abytes, unsigned astep,
                 unsigned char nc, unsigned nstep) {
    unsigned char k[KEYBYTES];
    unsigned char p[pbytes];
    unsigned char a[abytes];
    unsigned char n[NONCEBYTES];
    unsigned char c[pbytes+TAGBYTES];
    unsigned i;
    for (i=0; i<KEYBYTES; i++) k[i] = kc + i * kstep;
    for (i=0; i<pbytes; i++) p[i] = pc + i * pstep;
    for (i=0; i<abytes; i++) a[i] = ac + i * astep;
    for (i=0; i<NONCEBYTES; i++) n[i] = nc + i * nstep;
    ocb_encrypt(c, k, n, a, abytes, p, pbytes);
    printf("\n  RC6-%d/%d/%d (%d-bit blocks), %d-bit tags\n  K: ",
        BLOCKBYTES*8/4, RC6_RNDS, KEYBYTES, BLOCKBYTES*8, TAGBYTES*8);
    for (i=0; i<KEYBYTES; i++) {printf("%02X", k[i]);} printf("\n  N: ");
    for (i=0; i<NONCEBYTES; i++) {printf("%02X", n[i]);} printf("\n  A: ");
    for (i=0; i<abytes; i++) {printf("%02X", a[i]);} printf("\n  P: ");
    for (i=0; i<pbytes; i++) {printf("%02X", p[i]);} printf("\n  C: ");
    for (i=0; i<pbytes+TAGBYTES; i++) {printf("%02X", c[i]);} printf("\n\n");
}

int main() {
    unsigned char S[128];
    unsigned char key[KEYBYTES] = {0,};
    unsigned char nonce[NONCEBYTES] = {0,};
    unsigned char p[128] = {0,};
    unsigned char final[TAGBYTES];
    unsigned char *c;
    unsigned i, next;
    int result;
    
    if (0 && BLOCKBYTES==8) {
        pvec(0x00,1, 0,0,0, 0,0,0, 0x00,1);
        pvec(0x00,1, 0,4,1, 0,4,1, 0x00,1);
        pvec(0x00,1, 0,8,1, 0,8,1, 0x00,1);
        pvec(0x00,1, 0,20,1, 0,20,1, 0x00,1);
        return 0;
        pvec(0x81,1, 0,0,0, 0,0,0, 0xF0,1);
        pvec(0x91,1, 1,4,1, 5,4,1, 0xF1,1);
        pvec(0xA1,1, 2,8,1, 6,8,1, 0xF2,1);
        pvec(0xB1,1, 3,12,1, 7,12,1, 0xF3,1);
        pvec(0xC1,1, 4,16,1, 8,16,1, 0xF4,1);
    } else if (0 && BLOCKBYTES==24) {
        pvec(0x81,1, 0,0,0, 0,0,0, 0xF0,1);
        pvec(0x91,1, 1,12,1, 5,12,1, 0xF1,1);
        pvec(0xA1,1, 2,24,1, 6,24,1, 0xF2,1);
        pvec(0xB1,1, 3,36,1, 7,36,1, 0xF3,1);
        pvec(0xC1,1, 4,48,1, 8,48,1, 0xF4,1);
    } else if (0 && BLOCKBYTES==32) {
        pvec(0x00,1, 0,80,1, 0,80,1, 0x00,1);
        return 0;
        pvec(0x81,1, 0,0,0, 0,0,0, 0xF0,1);
        pvec(0x91,1, 1,12,1, 5,12,1, 0xF1,1);
        pvec(0xA1,1, 2,24,1, 6,24,1, 0xF2,1);
        pvec(0xB1,1, 3,36,1, 7,36,1, 0xF3,1);
        pvec(0xC1,1, 4,48,1, 8,48,1, 0xF4,1);
    }
    
    for (i=0; i<128; i++) S[i] = i;
    for (i=0; i<KEYBYTES; i++) key[i] = i;
    
    /* Encrypt and output RFC vector */
    c = malloc(16256+384*TAGBYTES);
    nonce[NONCEBYTES-1] = 1;
    next = 0;
    for (i=0; i<128; i++) {
        ocb_encrypt(c+next, key, nonce, S, i, S, i);
        next = next + i + TAGBYTES;
        nonce[NONCEBYTES-1]++; if (!nonce[NONCEBYTES-1]) nonce[NONCEBYTES-2]++;
        ocb_encrypt(c+next, key, nonce, S, 0, S, i);
        next = next + i + TAGBYTES;
        nonce[NONCEBYTES-1]++; if (!nonce[NONCEBYTES-1]) nonce[NONCEBYTES-2]++;
        ocb_encrypt(c+next, key, nonce, S, i, S, 0);
        next = next + TAGBYTES;
        nonce[NONCEBYTES-1]++; if (!nonce[NONCEBYTES-1]) nonce[NONCEBYTES-2]++;
    }
    ocb_encrypt(final, key, nonce, c, next, S, 0);
    printf("KEYBITS %d, TAGBITS %d, Tag ", KEYBYTES*8, TAGBYTES*8);
    for (i=0; i<TAGBYTES; i++) {printf("%02X", final[i]);} printf("\n");
    
    /* Decrypt and test for all zeros and authenticity */
    result = ocb_decrypt(p, key, nonce, c, next, final, TAGBYTES);
    if (result) { printf("FAIL\n"); return 0; }
    nonce[NONCEBYTES-2] = 0;
    nonce[NONCEBYTES-1] = 1;
    next = 0;
    for (i=0; i<128; i++) {
        result = ocb_decrypt(p, key, nonce, S, i, c+next, i+TAGBYTES);
        if (result || memcmp(p,S,i)) { printf("FAIL\n"); return 0; }
        next = next + i + TAGBYTES;
        nonce[NONCEBYTES-1]++; if (!nonce[NONCEBYTES-1]) nonce[NONCEBYTES-2]++;
        result = ocb_decrypt(p, key, nonce, S, 0, c+next, i+TAGBYTES);
        if (result || memcmp(p,S,i)) { printf("FAIL\n"); return 0; }
        next = next + i + TAGBYTES;
        nonce[NONCEBYTES-1]++; if (!nonce[NONCEBYTES-1]) nonce[NONCEBYTES-2]++;
        result = ocb_decrypt(p, key, nonce, S, i, c+next, TAGBYTES);
        if (result || memcmp(p,S,i)) { printf("FAIL\n"); return 0; }
        next = next + TAGBYTES;
        nonce[NONCEBYTES-1]++; if (!nonce[NONCEBYTES-1]) nonce[NONCEBYTES-2]++;
    }
    free(c);
    return 0;
}
