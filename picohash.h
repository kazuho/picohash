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
 * The MD5 implementation is based on a public domain implementation written by
 * Solar Designer <solar@openwall.com> in 2001, which is used by Dovecot.
 *
 *
 * The SHA1 implementation is based on the reference implementation found in RFC
 * 6234, provided under the following license:
 *
 * Copyright (c) 2011 IETF Trust and the persons identified as
 * authors of the code.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and
 *   the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF Trust, nor
 *   the names of specific contributors, may be used to endorse or
 *   promote products derived from this software without specific
 *   prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _picohash_h_
#define _picohash_h_

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#define PICOHASH_MD5_BLOCK_LENGTH 64
#define PICOHASH_MD5_DIGEST_LENGTH 16

typedef struct {
    uint_fast32_t lo, hi;
    uint_fast32_t a, b, c, d;
    unsigned char buffer[64];
    uint_fast32_t block[PICOHASH_MD5_DIGEST_LENGTH];
} _picohash_md5_ctx_t;

static void _picohash_md5_init(_picohash_md5_ctx_t *ctx);
static void _picohash_md5_update(_picohash_md5_ctx_t *ctx, const void *data, size_t size);
static void _picohash_md5_final(_picohash_md5_ctx_t *ctx, void *digest);

#define PICOHASH_SHA1_BLOCK_LENGTH 64
#define PICOHASH_SHA1_DIGEST_LENGTH 20

typedef struct {
    uint32_t Intermediate_Hash[PICOHASH_SHA1_DIGEST_LENGTH / 4];
    uint32_t Length_Low;
    uint32_t Length_High;
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];
} _picohash_sha1_ctx_t;

static void _picohash_sha1_init(_picohash_sha1_ctx_t *ctx);
static void _picohash_sha1_update(_picohash_sha1_ctx_t *ctx, const void *input, size_t len);
static void _picohash_sha1_final(_picohash_sha1_ctx_t *ctx, void *digest);

#define PICOHASH_MAX_BLOCK_LENGTH 64
#define PICOHASH_MAX_DIGEST_LENGTH 20

typedef struct {
    union {
        _picohash_md5_ctx_t _md5;
        _picohash_sha1_ctx_t _sha1;
    };
    size_t block_length;
    size_t digest_length;
    void (*_reset)(void *ctx);
    void (*_update)(void *ctx, const void *input, size_t len);
    void (*_final)(void *ctx, void *digest);
    struct {
        unsigned char key[PICOHASH_MAX_BLOCK_LENGTH];
        void (*hash_reset)(void *ctx);
        void (*hash_final)(void *ctx, void *digest);
    } _hmac;
} picohash_ctx_t;

static void picohash_init_md5(picohash_ctx_t *ctx);
static void picohash_init_sha1(picohash_ctx_t *ctx);
static void picohash_update(picohash_ctx_t *ctx, const void *input, size_t len);
static void picohash_final(picohash_ctx_t *ctx, void *digest);
static void picohash_reset(picohash_ctx_t *ctx);

static void picohash_init_hmac(picohash_ctx_t *ctx, void (*initf)(picohash_ctx_t *), const void *key, size_t key_len);

/* following are private definitions */

/*
 * The basic MD5 functions.
 *
 * F is optimized compared to its RFC 1321 definition just like in Colin
 * Plumb's implementation.
 */
#define _PICOHASH_MD5_F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define _PICOHASH_MD5_G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define _PICOHASH_MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define _PICOHASH_MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))

/*
 * The MD5 transformation for all four rounds.
 */
#define _PICOHASH_MD5_STEP(f, a, b, c, d, x, t, s)                                                                                 \
    (a) += f((b), (c), (d)) + (x) + (t);                                                                                           \
    (a) = (((a) << (s)) | (((a)&0xffffffff) >> (32 - (s))));                                                                       \
    (a) += (b);

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures which tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define _PICOHASH_MD5_SET(n) (*(const uint32_t *)&ptr[(n)*4])
#define _PICOHASH_MD5_GET(n) _PICOHASH_MD5_SET(n)
#else
#define _PICOHASH_MD5_SET(n)                                                                                                       \
    (ctx->block[(n)] = (uint_fast32_t)ptr[(n)*4] | ((uint_fast32_t)ptr[(n)*4 + 1] << 8) | ((uint_fast32_t)ptr[(n)*4 + 2] << 16) |  \
                       ((uint_fast32_t)ptr[(n)*4 + 3] << 24))
#define _PICOHASH_MD5_GET(n) (ctx->block[(n)])
#endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There're no alignment requirements.
 */
static const void *_picohash_md5_body(_picohash_md5_ctx_t *ctx, const void *data, size_t size)
{
    const unsigned char *ptr;
    uint_fast32_t a, b, c, d;
    uint_fast32_t saved_a, saved_b, saved_c, saved_d;

    ptr = data;

    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        /* Round 1 */
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, a, b, c, d, _PICOHASH_MD5_SET(0), 0xd76aa478, 7)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, d, a, b, c, _PICOHASH_MD5_SET(1), 0xe8c7b756, 12)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, c, d, a, b, _PICOHASH_MD5_SET(2), 0x242070db, 17)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, b, c, d, a, _PICOHASH_MD5_SET(3), 0xc1bdceee, 22)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, a, b, c, d, _PICOHASH_MD5_SET(4), 0xf57c0faf, 7)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, d, a, b, c, _PICOHASH_MD5_SET(5), 0x4787c62a, 12)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, c, d, a, b, _PICOHASH_MD5_SET(6), 0xa8304613, 17)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, b, c, d, a, _PICOHASH_MD5_SET(7), 0xfd469501, 22)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, a, b, c, d, _PICOHASH_MD5_SET(8), 0x698098d8, 7)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, d, a, b, c, _PICOHASH_MD5_SET(9), 0x8b44f7af, 12)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, c, d, a, b, _PICOHASH_MD5_SET(10), 0xffff5bb1, 17)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, b, c, d, a, _PICOHASH_MD5_SET(11), 0x895cd7be, 22)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, a, b, c, d, _PICOHASH_MD5_SET(12), 0x6b901122, 7)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, d, a, b, c, _PICOHASH_MD5_SET(13), 0xfd987193, 12)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, c, d, a, b, _PICOHASH_MD5_SET(14), 0xa679438e, 17)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_F, b, c, d, a, _PICOHASH_MD5_SET(15), 0x49b40821, 22)

        /* Round 2 */
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, a, b, c, d, _PICOHASH_MD5_GET(1), 0xf61e2562, 5)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, d, a, b, c, _PICOHASH_MD5_GET(6), 0xc040b340, 9)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, c, d, a, b, _PICOHASH_MD5_GET(11), 0x265e5a51, 14)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, b, c, d, a, _PICOHASH_MD5_GET(0), 0xe9b6c7aa, 20)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, a, b, c, d, _PICOHASH_MD5_GET(5), 0xd62f105d, 5)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, d, a, b, c, _PICOHASH_MD5_GET(10), 0x02441453, 9)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, c, d, a, b, _PICOHASH_MD5_GET(15), 0xd8a1e681, 14)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, b, c, d, a, _PICOHASH_MD5_GET(4), 0xe7d3fbc8, 20)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, a, b, c, d, _PICOHASH_MD5_GET(9), 0x21e1cde6, 5)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, d, a, b, c, _PICOHASH_MD5_GET(14), 0xc33707d6, 9)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, c, d, a, b, _PICOHASH_MD5_GET(3), 0xf4d50d87, 14)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, b, c, d, a, _PICOHASH_MD5_GET(8), 0x455a14ed, 20)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, a, b, c, d, _PICOHASH_MD5_GET(13), 0xa9e3e905, 5)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, d, a, b, c, _PICOHASH_MD5_GET(2), 0xfcefa3f8, 9)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, c, d, a, b, _PICOHASH_MD5_GET(7), 0x676f02d9, 14)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_G, b, c, d, a, _PICOHASH_MD5_GET(12), 0x8d2a4c8a, 20)

        /* Round 3 */
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, a, b, c, d, _PICOHASH_MD5_GET(5), 0xfffa3942, 4)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, d, a, b, c, _PICOHASH_MD5_GET(8), 0x8771f681, 11)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, c, d, a, b, _PICOHASH_MD5_GET(11), 0x6d9d6122, 16)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, b, c, d, a, _PICOHASH_MD5_GET(14), 0xfde5380c, 23)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, a, b, c, d, _PICOHASH_MD5_GET(1), 0xa4beea44, 4)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, d, a, b, c, _PICOHASH_MD5_GET(4), 0x4bdecfa9, 11)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, c, d, a, b, _PICOHASH_MD5_GET(7), 0xf6bb4b60, 16)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, b, c, d, a, _PICOHASH_MD5_GET(10), 0xbebfbc70, 23)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, a, b, c, d, _PICOHASH_MD5_GET(13), 0x289b7ec6, 4)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, d, a, b, c, _PICOHASH_MD5_GET(0), 0xeaa127fa, 11)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, c, d, a, b, _PICOHASH_MD5_GET(3), 0xd4ef3085, 16)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, b, c, d, a, _PICOHASH_MD5_GET(6), 0x04881d05, 23)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, a, b, c, d, _PICOHASH_MD5_GET(9), 0xd9d4d039, 4)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, d, a, b, c, _PICOHASH_MD5_GET(12), 0xe6db99e5, 11)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, c, d, a, b, _PICOHASH_MD5_GET(15), 0x1fa27cf8, 16)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_H, b, c, d, a, _PICOHASH_MD5_GET(2), 0xc4ac5665, 23)

        /* Round 4 */
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, a, b, c, d, _PICOHASH_MD5_GET(0), 0xf4292244, 6)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, d, a, b, c, _PICOHASH_MD5_GET(7), 0x432aff97, 10)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, c, d, a, b, _PICOHASH_MD5_GET(14), 0xab9423a7, 15)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, b, c, d, a, _PICOHASH_MD5_GET(5), 0xfc93a039, 21)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, a, b, c, d, _PICOHASH_MD5_GET(12), 0x655b59c3, 6)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, d, a, b, c, _PICOHASH_MD5_GET(3), 0x8f0ccc92, 10)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, c, d, a, b, _PICOHASH_MD5_GET(10), 0xffeff47d, 15)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, b, c, d, a, _PICOHASH_MD5_GET(1), 0x85845dd1, 21)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, a, b, c, d, _PICOHASH_MD5_GET(8), 0x6fa87e4f, 6)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, d, a, b, c, _PICOHASH_MD5_GET(15), 0xfe2ce6e0, 10)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, c, d, a, b, _PICOHASH_MD5_GET(6), 0xa3014314, 15)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, b, c, d, a, _PICOHASH_MD5_GET(13), 0x4e0811a1, 21)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, a, b, c, d, _PICOHASH_MD5_GET(4), 0xf7537e82, 6)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, d, a, b, c, _PICOHASH_MD5_GET(11), 0xbd3af235, 10)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, c, d, a, b, _PICOHASH_MD5_GET(2), 0x2ad7d2bb, 15)
        _PICOHASH_MD5_STEP(_PICOHASH_MD5_I, b, c, d, a, _PICOHASH_MD5_GET(9), 0xeb86d391, 21)

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ptr += 64;
    } while (size -= 64);

    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;

    return ptr;
}

inline void _picohash_md5_init(_picohash_md5_ctx_t *ctx)
{
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;

    ctx->lo = 0;
    ctx->hi = 0;
}

inline void _picohash_md5_update(_picohash_md5_ctx_t *ctx, const void *data, size_t size)
{
    uint_fast32_t saved_lo;
    unsigned long used, free;

    saved_lo = ctx->lo;
    if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
        ctx->hi++;
    ctx->hi += size >> 29;

    used = saved_lo & 0x3f;

    if (used) {
        free = 64 - used;

        if (size < free) {
            memcpy(&ctx->buffer[used], data, size);
            return;
        }

        memcpy(&ctx->buffer[used], data, free);
        data = (const unsigned char *)data + free;
        size -= free;
        _picohash_md5_body(ctx, ctx->buffer, 64);
    }

    if (size >= 64) {
        data = _picohash_md5_body(ctx, data, size & ~(unsigned long)0x3f);
        size &= 0x3f;
    }

    memcpy(ctx->buffer, data, size);
}

inline void _picohash_md5_final(_picohash_md5_ctx_t *ctx, void *_digest)
{
    unsigned char *digest = _digest;
    unsigned long used, free;

    used = ctx->lo & 0x3f;

    ctx->buffer[used++] = 0x80;

    free = 64 - used;

    if (free < 8) {
        memset(&ctx->buffer[used], 0, free);
        _picohash_md5_body(ctx, ctx->buffer, 64);
        used = 0;
        free = 64;
    }

    memset(&ctx->buffer[used], 0, free - 8);

    ctx->lo <<= 3;
    ctx->buffer[56] = ctx->lo;
    ctx->buffer[57] = ctx->lo >> 8;
    ctx->buffer[58] = ctx->lo >> 16;
    ctx->buffer[59] = ctx->lo >> 24;
    ctx->buffer[60] = ctx->hi;
    ctx->buffer[61] = ctx->hi >> 8;
    ctx->buffer[62] = ctx->hi >> 16;
    ctx->buffer[63] = ctx->hi >> 24;

    _picohash_md5_body(ctx, ctx->buffer, 64);

    digest[0] = ctx->a;
    digest[1] = ctx->a >> 8;
    digest[2] = ctx->a >> 16;
    digest[3] = ctx->a >> 24;
    digest[4] = ctx->b;
    digest[5] = ctx->b >> 8;
    digest[6] = ctx->b >> 16;
    digest[7] = ctx->b >> 24;
    digest[8] = ctx->c;
    digest[9] = ctx->c >> 8;
    digest[10] = ctx->c >> 16;
    digest[11] = ctx->c >> 24;
    digest[12] = ctx->d;
    digest[13] = ctx->d >> 8;
    digest[14] = ctx->d >> 16;
    digest[15] = ctx->d >> 24;

    memset(ctx, 0, sizeof(*ctx));
}

static inline void _picohash_sha1_process_message_block(_picohash_sha1_ctx_t *context)
{
#define _PICOHASH_SHA1_Ch(x, y, z) (((x) & ((y) ^ (z))) ^ (z))
#define _PICOHASH_SHA1_Maj(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define _PICOHASH_SHA1_Parity(x, y, z) ((x) ^ (y) ^ (z))
#define _PICOHASH_SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))

    /* Constants defined in FIPS 180-3, section 4.2.1 */
    const uint32_t K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
    int t;                  /* Loop counter */
    uint32_t temp;          /* Temporary word value */
    uint32_t W[80];         /* Word sequence */
    uint32_t A, B, C, D, E; /* Word buffers */

    /*
     * Initialize the first 16 words in the array W
     */
    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)context->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++)
        W[t] = _PICOHASH_SHA1_ROTL(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for (t = 0; t < 20; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Ch(B, C, D) + E + W[t] + K[0];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Parity(B, C, D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Maj(B, C, D) + E + W[t] + K[2];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Parity(B, C, D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Message_Block_Index = 0;

#undef _PICOHASH_SHA1_Ch
#undef _PICOHASH_SHA1_Maj
#undef _PICOHASH_SHA1_Parity
#undef _PICOHASH_SHA1_ROTL
}

static inline void _picohash_sha1_pad_message(_picohash_sha1_ctx_t *context, uint8_t Pad_Byte)
{
    /*
     * Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second
     * block.
     */
    if (context->Message_Block_Index >= (PICOHASH_SHA1_BLOCK_LENGTH - 8)) {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
        while (context->Message_Block_Index < PICOHASH_SHA1_BLOCK_LENGTH)
            context->Message_Block[context->Message_Block_Index++] = 0;

        _picohash_sha1_process_message_block(context);
    } else
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

    while (context->Message_Block_Index < (PICOHASH_SHA1_BLOCK_LENGTH - 8))
        context->Message_Block[context->Message_Block_Index++] = 0;

    /*
     * Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (uint8_t)(context->Length_High >> 24);
    context->Message_Block[57] = (uint8_t)(context->Length_High >> 16);
    context->Message_Block[58] = (uint8_t)(context->Length_High >> 8);
    context->Message_Block[59] = (uint8_t)(context->Length_High);
    context->Message_Block[60] = (uint8_t)(context->Length_Low >> 24);
    context->Message_Block[61] = (uint8_t)(context->Length_Low >> 16);
    context->Message_Block[62] = (uint8_t)(context->Length_Low >> 8);
    context->Message_Block[63] = (uint8_t)(context->Length_Low);

    _picohash_sha1_process_message_block(context);
}

static inline void _picohash_sha1_finalize(_picohash_sha1_ctx_t *context, uint8_t Pad_Byte)
{
    int i;
    _picohash_sha1_pad_message(context, Pad_Byte);
    /* message may be sensitive, clear it out */
    for (i = 0; i < PICOHASH_SHA1_BLOCK_LENGTH; ++i)
        context->Message_Block[i] = 0;
    context->Length_High = 0; /* and clear length */
    context->Length_Low = 0;
}

inline void _picohash_sha1_init(_picohash_sha1_ctx_t *context)
{
    context->Length_High = context->Length_Low = 0;
    context->Message_Block_Index = 0;

    /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;
}

inline void _picohash_sha1_update(_picohash_sha1_ctx_t *context, const void *_message_array, size_t length)
{
    const uint8_t *message_array = _message_array;
    uint32_t addTemp;

    while (length--) {
        context->Message_Block[context->Message_Block_Index++] = *message_array;
        addTemp = context->Length_Low;
        if ((context->Length_Low += 8) < addTemp)
            ++context->Length_High;
        if (context->Message_Block_Index == PICOHASH_SHA1_BLOCK_LENGTH)
            _picohash_sha1_process_message_block(context);

        message_array++;
    }
}

inline void _picohash_sha1_final(_picohash_sha1_ctx_t *context, void *_Message_Digest)
{
    unsigned char *Message_Digest = _Message_Digest;
    int i;

    _picohash_sha1_finalize(context, 0x80);

    for (i = 0; i < PICOHASH_SHA1_DIGEST_LENGTH; ++i)
        Message_Digest[i] = (uint8_t)(context->Intermediate_Hash[i >> 2] >> (8 * (3 - (i & 0x03))));
}

inline void picohash_init_md5(picohash_ctx_t *ctx)
{
    ctx->block_length = PICOHASH_MD5_BLOCK_LENGTH;
    ctx->digest_length = PICOHASH_MD5_DIGEST_LENGTH;
    ctx->_reset = (void *)_picohash_md5_init;
    ctx->_update = (void *)_picohash_md5_update;
    ctx->_final = (void *)_picohash_md5_final;

    _picohash_md5_init(&ctx->_md5);
}

inline void picohash_init_sha1(picohash_ctx_t *ctx)
{
    ctx->block_length = PICOHASH_SHA1_BLOCK_LENGTH;
    ctx->digest_length = PICOHASH_SHA1_DIGEST_LENGTH;
    ctx->_reset = (void *)_picohash_sha1_init;
    ctx->_update = (void *)_picohash_sha1_update;
    ctx->_final = (void *)_picohash_sha1_final;
    _picohash_sha1_init(&ctx->_sha1);
}

inline void picohash_update(picohash_ctx_t *ctx, const void *input, size_t len)
{
    ctx->_update(ctx, input, len);
}

inline void picohash_final(picohash_ctx_t *ctx, void *digest)
{
    ctx->_final(ctx, digest);
}

inline void picohash_reset(picohash_ctx_t *ctx)
{
    ctx->_reset(ctx);
}

static inline void _picohash_hmac_apply_key(picohash_ctx_t *ctx, unsigned char delta)
{
    size_t i;
    for (i = 0; i != ctx->block_length; ++i)
        ctx->_hmac.key[i] ^= delta;
    picohash_update(ctx, ctx->_hmac.key, ctx->block_length);
    for (i = 0; i != ctx->block_length; ++i)
        ctx->_hmac.key[i] ^= delta;
}

static void _picohash_hmac_final(picohash_ctx_t *ctx, void *digest)
{
    unsigned char inner_digest[PICOHASH_MAX_DIGEST_LENGTH];

    ctx->_hmac.hash_final(ctx, inner_digest);

    ctx->_hmac.hash_reset(ctx);
    _picohash_hmac_apply_key(ctx, 0x5c);
    picohash_update(ctx, inner_digest, ctx->digest_length);
    memset(inner_digest, 0, ctx->digest_length);

    ctx->_hmac.hash_final(ctx, digest);
}

static inline void _picohash_hmac_reset(picohash_ctx_t *ctx)
{
    ctx->_hmac.hash_reset(ctx);
    _picohash_hmac_apply_key(ctx, 0x36);
}

inline void picohash_init_hmac(picohash_ctx_t *ctx, void (*initf)(picohash_ctx_t *), const void *key, size_t key_len)
{
    initf(ctx);

    memset(ctx->_hmac.key, 0, ctx->block_length);
    if (key_len > ctx->block_length) {
        /* hash the key if it is too long */
        picohash_update(ctx, key, key_len);
        picohash_final(ctx, ctx->_hmac.key);
        ctx->_hmac.hash_reset(ctx);
    } else {
        memcpy(ctx->_hmac.key, key, key_len);
    }

    /* replace reset and final function */
    ctx->_hmac.hash_reset = ctx->_reset;
    ctx->_hmac.hash_final = ctx->_final;
    ctx->_reset = (void *)_picohash_hmac_reset;
    ctx->_final = (void *)_picohash_hmac_final;

    /* start calculating the inner hash */
    _picohash_hmac_apply_key(ctx, 0x36);
}

#endif
