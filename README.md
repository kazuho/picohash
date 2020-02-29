picohash
===

picohash is a header-file-only implementation of MD5, SHA1, SHA224, SHA256, HMAC.

The code is placed under public domain.
It comes without any warranty, to the extent permitted by applicable law.

Calculating Hash
---

```
picohash_ctx_t ctx;
char digest[PICOHASH_MD5_DIGEST_LENGTH];

picohash_init_md5(&ctx);
picohash_update(&ctx, "hello", 5);
picohash_final(&ctx, digest);
```

Replace `md5` with `sha1`, `sha224`, `sha256` for your need.

Calculating HMAC
---

```
picohash_ctx_t ctx;
char digest[PICOHASH_SHA1_DIGEST_LENGTH];

picohash_init_hmac(&ctx, picohash_init_sha1, "my secret", strlen("my secret"));
picohash_update(&ctx, "hello", 5);
picohash_final(&ctx, digest);
```

Replace `md5` with `sha1`, `sha224`, `sha256` for your need.
