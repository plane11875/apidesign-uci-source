/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/provider.h"
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int UCI_SealInit(UCI_CIPHER_CTX *ctx, const UCI_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 UCI_PKEY **pubk, int npubk)
{
    unsigned char key[UCI_MAX_KEY_LENGTH];
    const OSSL_PROVIDER *prov;
    OSSL_LIB_CTX *libctx = NULL;
    UCI_PKEY_CTX *pctx = NULL;
    const UCI_CIPHER *cipher;
    int i, len;
    int rv = 0;

    if (type != NULL) {
        UCI_CIPHER_CTX_reset(ctx);
        if (!UCI_EncryptInit_ex(ctx, type, NULL, NULL, NULL))
            return 0;
    }
    if ((cipher = UCI_CIPHER_CTX_get0_cipher(ctx)) != NULL
            && (prov = UCI_CIPHER_get0_provider(cipher)) != NULL)
        libctx = ossl_provider_libctx(prov);
    if ((npubk <= 0) || !pubk)
        return 1;

    if (UCI_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;

    len = UCI_CIPHER_CTX_get_iv_length(ctx);
    if (len < 0 || RAND_priv_bytes_ex(libctx, iv, len, 0) <= 0)
        goto err;

    len = UCI_CIPHER_CTX_get_key_length(ctx);
    if (len < 0)
        goto err;

    if (!UCI_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;

    for (i = 0; i < npubk; i++) {
        size_t keylen = len;
        size_t outlen = UCI_PKEY_get_size(pubk[i]);

        pctx = UCI_PKEY_CTX_new_from_pkey(libctx, pubk[i], NULL);
        if (pctx == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_UCI_LIB);
            goto err;
        }

        if (UCI_PKEY_encrypt_init(pctx) <= 0
            || UCI_PKEY_encrypt(pctx, ek[i], &outlen, key, keylen) <= 0)
            goto err;
        ekl[i] = (int)outlen;
        UCI_PKEY_CTX_free(pctx);
    }
    pctx = NULL;
    rv = npubk;
err:
    UCI_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(key, sizeof(key));
    return rv;
}

int UCI_SealFinal(UCI_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    i = UCI_EncryptFinal_ex(ctx, out, outl);
    if (i)
        i = UCI_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    return i;
}
