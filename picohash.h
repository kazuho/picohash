/*
 * Copyright (c) 2015 Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 *
 * The MD5 implementation is based on the reference implementation found in RFC
 * 1321, provided under the following license:
 *
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#ifndef _picohash_h_
#define _picohash_h_

#include <inttypes.h>
#include <string.h>

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} picohash_md5_ctx_t;

/* Encodes input (uint32_t) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static void picohash_md5__encode(unsigned char *output, const uint32_t *input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

/* Decodes input (unsigned char) into output (uint32_t). Assumes len is
  a multiple of 4.
 */
static void picohash_md5__decode(uint32_t *output, const unsigned char *input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) | (((uint32_t)input[j + 2]) << 16) |
                    (((uint32_t)input[j + 3]) << 24);
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void picohash_md5__transform(uint32_t state[4], const unsigned char block[64])
{
#define PICOHASH__S11 7
#define PICOHASH__S12 12
#define PICOHASH__S13 17
#define PICOHASH__S14 22
#define PICOHASH__S21 5
#define PICOHASH__S22 9
#define PICOHASH__S23 14
#define PICOHASH__S24 20
#define PICOHASH__S31 4
#define PICOHASH__S32 11
#define PICOHASH__S33 16
#define PICOHASH__S34 23
#define PICOHASH__S41 6
#define PICOHASH__S42 10
#define PICOHASH__S43 15
#define PICOHASH__S44 21

/* F, G, H and I are basic MD5 functions.
 */
#define PICOHASH__F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define PICOHASH__G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define PICOHASH__H(x, y, z) ((x) ^ (y) ^ (z))
#define PICOHASH__I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define PICOHASH__ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define PICOHASH__FF(a, b, c, d, x, s, ac)                                                                                         \
    {                                                                                                                              \
        (a) += PICOHASH__F((b), (c), (d)) + (x) + (uint32_t)(ac);                                                                  \
        (a) = PICOHASH__ROTATE_LEFT((a), (s));                                                                                     \
        (a) += (b);                                                                                                                \
    }
#define PICOHASH__GG(a, b, c, d, x, s, ac)                                                                                         \
    {                                                                                                                              \
        (a) += PICOHASH__G((b), (c), (d)) + (x) + (uint32_t)(ac);                                                                  \
        (a) = PICOHASH__ROTATE_LEFT((a), (s));                                                                                     \
        (a) += (b);                                                                                                                \
    }
#define PICOHASH__HH(a, b, c, d, x, s, ac)                                                                                         \
    {                                                                                                                              \
        (a) += PICOHASH__H((b), (c), (d)) + (x) + (uint32_t)(ac);                                                                  \
        (a) = PICOHASH__ROTATE_LEFT((a), (s));                                                                                     \
        (a) += (b);                                                                                                                \
    }
#define PICOHASH__II(a, b, c, d, x, s, ac)                                                                                         \
    {                                                                                                                              \
        (a) += PICOHASH__I((b), (c), (d)) + (x) + (uint32_t)(ac);                                                                  \
        (a) = PICOHASH__ROTATE_LEFT((a), (s));                                                                                     \
        (a) += (b);                                                                                                                \
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    picohash_md5__decode(x, block, 64);

    /* Round 1 */
    PICOHASH__FF(a, b, c, d, x[0], PICOHASH__S11, 0xd76aa478);  /* 1 */
    PICOHASH__FF(d, a, b, c, x[1], PICOHASH__S12, 0xe8c7b756);  /* 2 */
    PICOHASH__FF(c, d, a, b, x[2], PICOHASH__S13, 0x242070db);  /* 3 */
    PICOHASH__FF(b, c, d, a, x[3], PICOHASH__S14, 0xc1bdceee);  /* 4 */
    PICOHASH__FF(a, b, c, d, x[4], PICOHASH__S11, 0xf57c0faf);  /* 5 */
    PICOHASH__FF(d, a, b, c, x[5], PICOHASH__S12, 0x4787c62a);  /* 6 */
    PICOHASH__FF(c, d, a, b, x[6], PICOHASH__S13, 0xa8304613);  /* 7 */
    PICOHASH__FF(b, c, d, a, x[7], PICOHASH__S14, 0xfd469501);  /* 8 */
    PICOHASH__FF(a, b, c, d, x[8], PICOHASH__S11, 0x698098d8);  /* 9 */
    PICOHASH__FF(d, a, b, c, x[9], PICOHASH__S12, 0x8b44f7af);  /* 10 */
    PICOHASH__FF(c, d, a, b, x[10], PICOHASH__S13, 0xffff5bb1); /* 11 */
    PICOHASH__FF(b, c, d, a, x[11], PICOHASH__S14, 0x895cd7be); /* 12 */
    PICOHASH__FF(a, b, c, d, x[12], PICOHASH__S11, 0x6b901122); /* 13 */
    PICOHASH__FF(d, a, b, c, x[13], PICOHASH__S12, 0xfd987193); /* 14 */
    PICOHASH__FF(c, d, a, b, x[14], PICOHASH__S13, 0xa679438e); /* 15 */
    PICOHASH__FF(b, c, d, a, x[15], PICOHASH__S14, 0x49b40821); /* 16 */

    /* Round 2 */
    PICOHASH__GG(a, b, c, d, x[1], PICOHASH__S21, 0xf61e2562);  /* 17 */
    PICOHASH__GG(d, a, b, c, x[6], PICOHASH__S22, 0xc040b340);  /* 18 */
    PICOHASH__GG(c, d, a, b, x[11], PICOHASH__S23, 0x265e5a51); /* 19 */
    PICOHASH__GG(b, c, d, a, x[0], PICOHASH__S24, 0xe9b6c7aa);  /* 20 */
    PICOHASH__GG(a, b, c, d, x[5], PICOHASH__S21, 0xd62f105d);  /* 21 */
    PICOHASH__GG(d, a, b, c, x[10], PICOHASH__S22, 0x2441453);  /* 22 */
    PICOHASH__GG(c, d, a, b, x[15], PICOHASH__S23, 0xd8a1e681); /* 23 */
    PICOHASH__GG(b, c, d, a, x[4], PICOHASH__S24, 0xe7d3fbc8);  /* 24 */
    PICOHASH__GG(a, b, c, d, x[9], PICOHASH__S21, 0x21e1cde6);  /* 25 */
    PICOHASH__GG(d, a, b, c, x[14], PICOHASH__S22, 0xc33707d6); /* 26 */
    PICOHASH__GG(c, d, a, b, x[3], PICOHASH__S23, 0xf4d50d87);  /* 27 */
    PICOHASH__GG(b, c, d, a, x[8], PICOHASH__S24, 0x455a14ed);  /* 28 */
    PICOHASH__GG(a, b, c, d, x[13], PICOHASH__S21, 0xa9e3e905); /* 29 */
    PICOHASH__GG(d, a, b, c, x[2], PICOHASH__S22, 0xfcefa3f8);  /* 30 */
    PICOHASH__GG(c, d, a, b, x[7], PICOHASH__S23, 0x676f02d9);  /* 31 */
    PICOHASH__GG(b, c, d, a, x[12], PICOHASH__S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    PICOHASH__HH(a, b, c, d, x[5], PICOHASH__S31, 0xfffa3942);  /* 33 */
    PICOHASH__HH(d, a, b, c, x[8], PICOHASH__S32, 0x8771f681);  /* 34 */
    PICOHASH__HH(c, d, a, b, x[11], PICOHASH__S33, 0x6d9d6122); /* 35 */
    PICOHASH__HH(b, c, d, a, x[14], PICOHASH__S34, 0xfde5380c); /* 36 */
    PICOHASH__HH(a, b, c, d, x[1], PICOHASH__S31, 0xa4beea44);  /* 37 */
    PICOHASH__HH(d, a, b, c, x[4], PICOHASH__S32, 0x4bdecfa9);  /* 38 */
    PICOHASH__HH(c, d, a, b, x[7], PICOHASH__S33, 0xf6bb4b60);  /* 39 */
    PICOHASH__HH(b, c, d, a, x[10], PICOHASH__S34, 0xbebfbc70); /* 40 */
    PICOHASH__HH(a, b, c, d, x[13], PICOHASH__S31, 0x289b7ec6); /* 41 */
    PICOHASH__HH(d, a, b, c, x[0], PICOHASH__S32, 0xeaa127fa);  /* 42 */
    PICOHASH__HH(c, d, a, b, x[3], PICOHASH__S33, 0xd4ef3085);  /* 43 */
    PICOHASH__HH(b, c, d, a, x[6], PICOHASH__S34, 0x4881d05);   /* 44 */
    PICOHASH__HH(a, b, c, d, x[9], PICOHASH__S31, 0xd9d4d039);  /* 45 */
    PICOHASH__HH(d, a, b, c, x[12], PICOHASH__S32, 0xe6db99e5); /* 46 */
    PICOHASH__HH(c, d, a, b, x[15], PICOHASH__S33, 0x1fa27cf8); /* 47 */
    PICOHASH__HH(b, c, d, a, x[2], PICOHASH__S34, 0xc4ac5665);  /* 48 */

    /* Round 4 */
    PICOHASH__II(a, b, c, d, x[0], PICOHASH__S41, 0xf4292244);  /* 49 */
    PICOHASH__II(d, a, b, c, x[7], PICOHASH__S42, 0x432aff97);  /* 50 */
    PICOHASH__II(c, d, a, b, x[14], PICOHASH__S43, 0xab9423a7); /* 51 */
    PICOHASH__II(b, c, d, a, x[5], PICOHASH__S44, 0xfc93a039);  /* 52 */
    PICOHASH__II(a, b, c, d, x[12], PICOHASH__S41, 0x655b59c3); /* 53 */
    PICOHASH__II(d, a, b, c, x[3], PICOHASH__S42, 0x8f0ccc92);  /* 54 */
    PICOHASH__II(c, d, a, b, x[10], PICOHASH__S43, 0xffeff47d); /* 55 */
    PICOHASH__II(b, c, d, a, x[1], PICOHASH__S44, 0x85845dd1);  /* 56 */
    PICOHASH__II(a, b, c, d, x[8], PICOHASH__S41, 0x6fa87e4f);  /* 57 */
    PICOHASH__II(d, a, b, c, x[15], PICOHASH__S42, 0xfe2ce6e0); /* 58 */
    PICOHASH__II(c, d, a, b, x[6], PICOHASH__S43, 0xa3014314);  /* 59 */
    PICOHASH__II(b, c, d, a, x[13], PICOHASH__S44, 0x4e0811a1); /* 60 */
    PICOHASH__II(a, b, c, d, x[4], PICOHASH__S41, 0xf7537e82);  /* 61 */
    PICOHASH__II(d, a, b, c, x[11], PICOHASH__S42, 0xbd3af235); /* 62 */
    PICOHASH__II(c, d, a, b, x[2], PICOHASH__S43, 0x2ad7d2bb);  /* 63 */
    PICOHASH__II(b, c, d, a, x[9], PICOHASH__S44, 0xeb86d391);  /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /* Zeroize sensitive information. */
    memset(x, 0, sizeof(x));

#undef PICOHASH__S11
#undef PICOHASH__S12
#undef PICOHASH__S13
#undef PICOHASH__S14
#undef PICOHASH__S21
#undef PICOHASH__S22
#undef PICOHASH__S23
#undef PICOHASH__S24
#undef PICOHASH__S31
#undef PICOHASH__S32
#undef PICOHASH__S33
#undef PICOHASH__S34
#undef PICOHASH__S41
#undef PICOHASH__S42
#undef PICOHASH__S43
#undef PICOHASH__S44
#undef PICOHASH__F
#undef PICOHASH__G
#undef PICOHASH__H
#undef PICOHASH__I
#undef PICOHASH__ROTATE_LEFT
#undef PICOHASH__FF
#undef PICOHASH__GG
#undef PICOHASH__HH
#undef PICOHASH__II
}

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void picohash_md5_init(picohash_md5_ctx_t *context)
{
    context->count[0] = context->count[1] = 0;
    /* Load magic initialization constants. */
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
static void picohash_md5_update(picohash_md5_ctx_t *context, const void *_input, size_t inputLen)
{
    const unsigned char *input = _input;
    size_t i, index, partLen;

    /* Compute number of bytes mod 64 */
    index = (unsigned int)((context->count[0] >> 3) & 0x3F);

    /* Update number of bits */
    if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
        context->count[1]++;
    context->count[1] += ((uint32_t)inputLen >> 29);

    partLen = 64 - index;

    /* Transform as many times as possible. */
    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        picohash_md5__transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
            picohash_md5__transform(context->state, &input[i]);

        index = 0;
    } else
        i = 0;

    /* Buffer remaining input */
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
static void picohash_md5_final(picohash_md5_ctx_t *context, unsigned char digest[16])
{
    static const unsigned char PADDING[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char bits[8];
    unsigned int index, padLen;

    /* Save number of bits */
    picohash_md5__encode(bits, context->count, 8);

    /* Pad out to 56 mod 64. */
    index = (unsigned int)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    picohash_md5_update(context, PADDING, padLen);

    /* Append length (before padding) */
    picohash_md5_update(context, bits, 8);

    /* Store state in digest */
    picohash_md5__encode(digest, context->state, 16);

    /* Zeroize sensitive information. */
    memset(context, 0, sizeof(*context));
}

#endif
