/* Copyright 2016 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// #include "mongoc-config.h"

#include "mongoc-crypto-common-crypto.c"

#include "mongoc-crypto-private.h"
#if defined(MONGOC_ENABLE_CRYPTO_LIBCRYPTO)
#include "mongoc-crypto-openssl-private.h"
#elif defined(MONGOC_ENABLE_CRYPTO_COMMON_CRYPTO)
#include "mongoc-crypto-common-crypto-private.h"
#elif defined(MONGOC_ENABLE_CRYPTO_CNG)
#include "mongoc-crypto-cng-private.h"
#endif

void
mongoc_crypto_init (mongoc_crypto_t *crypto)
{

   crypto->hmac_sha1 = mongoc_crypto_common_crypto_hmac_sha1;
   crypto->sha1 = mongoc_crypto_common_crypto_sha1;
#ifdef MONGOC_ENABLE_CRYPTO_LIBCRYPTO
   crypto->hmac_sha1 = mongoc_crypto_openssl_hmac_sha1;
   crypto->sha1 = mongoc_crypto_openssl_sha1;
#elif defined(MONGOC_ENABLE_CRYPTO_COMMON_CRYPTO)
   crypto->hmac_sha1 = mongoc_crypto_common_crypto_hmac_sha1;
   crypto->sha1 = mongoc_crypto_common_crypto_sha1;
#elif defined(MONGOC_ENABLE_CRYPTO_CNG)
   crypto->hmac_sha1 = mongoc_crypto_cng_hmac_sha1;
   crypto->sha1 = mongoc_crypto_cng_sha1;
#endif
}

void
mongoc_crypto_hmac_sha1 (mongoc_crypto_t *crypto,
                         const void *key,
                         int key_len,
                         const unsigned char *d,
                         int n,
                         unsigned char *md /* OUT */)
{
   crypto->hmac_sha1 (crypto, key, key_len, d, n, md);
}

my_bool
mongoc_crypto_sha1 (mongoc_crypto_t *crypto,
                    const unsigned char *input,
                    const size_t input_len,
                    unsigned char *output /* OUT */)
{
   return crypto->sha1 (crypto, input, input_len, output);
}
