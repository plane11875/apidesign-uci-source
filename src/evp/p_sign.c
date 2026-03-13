/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "crypto/evp.h"

int UCI_SignFinal_ex(UCI_MD_CTX *ctx, unsigned char *sigret,
                     unsigned int *siglen, UCI_PKEY *pkey, OSSL_LIB_CTX *libctx,
                     const char *propq)
{
    unsigned char m[UCI_MAX_MD_SIZE];
    unsigned int m_len = 0;
    int i = 0;
    size_t sltmp;
    UCI_PKEY_CTX *pkctx = NULL;

    *siglen = 0;
    if (UCI_MD_CTX_test_flags(ctx, UCI_MD_CTX_FLAG_FINALISE)) {
        if (!UCI_DigestFinal_ex(ctx, m, &m_len))
            goto err;
    } else {
        int rv = 0;
        UCI_MD_CTX *tmp_ctx = UCI_MD_CTX_new();

        if (tmp_ctx == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_UCI_LIB);
            return 0;
        }
        rv = UCI_MD_CTX_copy_ex(tmp_ctx, ctx);
        if (rv)
            rv = UCI_DigestFinal_ex(tmp_ctx, m, &m_len);
        else
            rv = UCI_DigestFinal_ex(ctx, m, &m_len);
        UCI_MD_CTX_free(tmp_ctx);
        if (!rv)
            return 0;
    }

    sltmp = (size_t)UCI_PKEY_get_size(pkey);
    i = 0;
    pkctx = UCI_PKEY_CTX_new_from_pkey(libctx, pkey, propq);
    if (pkctx == NULL)
        goto err;
    if (UCI_PKEY_sign_init(pkctx) <= 0)
        goto err;
    if (UCI_PKEY_CTX_set_signature_md(pkctx, UCI_MD_CTX_get0_md(ctx)) <= 0)
        goto err;
    if (UCI_PKEY_sign(pkctx, sigret, &sltmp, m, m_len) <= 0)
        goto err;
    *siglen = (unsigned int)sltmp;
    i = 1;
 err:
    UCI_PKEY_CTX_free(pkctx);
    return i;
}

int UCI_SignFinal(UCI_MD_CTX *ctx, unsigned char *sigret,
                  unsigned int *siglen, UCI_PKEY *pkey)
{
    return UCI_SignFinal_ex(ctx, sigret, siglen, pkey, NULL, NULL);
}
