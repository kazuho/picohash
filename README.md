picohash
===

picohash is a header-file-only implementation of MD5, SHA1, HMAC.

Using MD5
---

```
picohash_ctx_t ctx;
char digest[PICOHASH_MD5_DIGEST_LENGTH];

picohash_init_md5(&ctx);
picohash_update(&ctx, "hello", 5);
picohash_digest(&ctx, digest);
```

Using SHA1
---

```
picohash_ctx_t ctx;
char digest[PICOHASH_SHA1_DIGEST_LENGTH];

picohash_init_sha1(&ctx);
picohash_update(&ctx, "hello", 5);
picohash_digest(&ctx, digest);
```

Using HMAC
---

```
picohash_ctx_t ctx;
char digest[PICOHASH_SHA1_DIGEST_LENGTH];

picohash_init_hmac(&ctx, picohash_init_sha1, "my secret", strlen("my secret"));
picohash_update(&ctx, "hello", 5);
picohash_digest(&ctx, digest);
```
