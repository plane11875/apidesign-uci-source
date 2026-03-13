/*
 * Copyright 2018-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include "crypto/evp.h"
#include "internal/numbers.h"
#include "internal/provider.h"
#include "uci_local.h"
#include "internal/param_build_set.h"

UCI_KDF_CTX *UCI_KDF_CTX_new(UCI_KDF *kdf)
{
    UCI_KDF_CTX *ctx = NULL;

    if (kdf == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(UCI_KDF_CTX));
    if (ctx == NULL
        || (ctx->algctx = kdf->newctx(ossl_provider_ctx(kdf->prov))) == NULL
        || !UCI_KDF_up_ref(kdf)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_UCI_LIB);
        if (ctx != NULL)
            kdf->freectx(ctx->algctx);
        OPENSSL_free(ctx);
        ctx = NULL;
    } else {
        ctx->meth = kdf;
    }
    return ctx;
}

void UCI_KDF_CTX_free(UCI_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;
    ctx->meth->freectx(ctx->algctx);
    ctx->algctx = NULL;
    UCI_KDF_free(ctx->meth);
    OPENSSL_free(ctx);
}

UCI_KDF_CTX *UCI_KDF_CTX_dup(const UCI_KDF_CTX *src)
{
    UCI_KDF_CTX *dst;

    if (src == NULL || src->algctx == NULL || src->meth->dupctx == NULL)
        return NULL;

    dst = OPENSSL_malloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    memcpy(dst, src, sizeof(*dst));
    if (!UCI_KDF_up_ref(dst->meth)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_UCI_LIB);
        OPENSSL_free(dst);
        return NULL;
    }

    dst->algctx = src->meth->dupctx(src->algctx);
    if (dst->algctx == NULL) {
        UCI_KDF_CTX_free(dst);
        return NULL;
    }
    return dst;
}

int uci_kdf_get_number(const UCI_KDF *kdf)
{
    return kdf->name_id;
}

const char *UCI_KDF_get0_name(const UCI_KDF *kdf)
{
    return kdf->type_name;
}

const char *UCI_KDF_get0_description(const UCI_KDF *kdf)
{
    return kdf->description;
}

int UCI_KDF_is_a(const UCI_KDF *kdf, const char *name)
{
    return kdf != NULL && uci_is_a(kdf->prov, kdf->name_id, NULL, name);
}

const OSSL_PROVIDER *UCI_KDF_get0_provider(const UCI_KDF *kdf)
{
    return kdf->prov;
}

const UCI_KDF *UCI_KDF_CTX_kdf(UCI_KDF_CTX *ctx)
{
    return ctx->meth;
}

void UCI_KDF_CTX_reset(UCI_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->meth->reset != NULL)
        ctx->meth->reset(ctx->algctx);
}

size_t UCI_KDF_CTX_get_kdf_size(UCI_KDF_CTX *ctx)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    size_t s = 0;

    if (ctx == NULL)
        return 0;

    *params = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &s);
    if (ctx->meth->get_ctx_params != NULL
        && ctx->meth->get_ctx_params(ctx->algctx, params))
            return s;
    if (ctx->meth->get_params != NULL
        && ctx->meth->get_params(params))
            return s;
    return 0;
}

int UCI_KDF_derive(UCI_KDF_CTX *ctx, unsigned char *key, size_t keylen,
                   const OSSL_PARAM params[])
{
    if (ctx == NULL)
        return 0;

    return ctx->meth->derive(ctx->algctx, key, keylen, params);
}

struct convert_key {
    const char *name;
    OSSL_PARAM *param;
};

static int convert_key_cb(const OSSL_PARAM params[], void *arg)
{
    struct convert_key *ckey = arg;
    const OSSL_PARAM *raw_bytes;
    unsigned char *data;
    size_t len;

    raw_bytes = OSSL_PARAM_locate_const(params, OSSL_SKEY_PARAM_RAW_BYTES);
    if (raw_bytes == NULL)
        return 0;

    if (!OSSL_PARAM_get_octet_string_ptr(raw_bytes, (const void **)&data, &len))
        return 0;

    *ckey->param = OSSL_PARAM_construct_octet_string(ckey->name, data, len);
    return 1;
}

int UCI_KDF_CTX_set_SKEY(UCI_KDF_CTX *ctx, UCI_SKEY *key, const char *paramname)
{
    struct convert_key ckey;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END,
        OSSL_PARAM_END,
    };

    if (ctx == NULL)
        return 0;

    ckey.name = (paramname != NULL) ? paramname : OSSL_KDF_PARAM_KEY;

    if (ctx->meth->set_skey != NULL && ctx->meth->prov == key->skeymgmt->prov)
        return ctx->meth->set_skey(ctx->algctx, key->keydata, ckey.name);

    /*
     * We can't use the opaque key directly.
     * Let's try to export it and set the ctx params in a traditional manner.
     */
    ckey.param = &params[0];

    if (!ctx->meth->set_ctx_params)
        return 0;

    if (UCI_SKEY_export(key, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
                        convert_key_cb, &ckey))
        return ctx->meth->set_ctx_params(ctx->algctx, params);

    return 0;
}

UCI_SKEY *UCI_KDF_derive_SKEY(UCI_KDF_CTX *ctx, UCI_SKEYMGMT *mgmt,
                              const char *key_type, const char *propquery,
                              size_t keylen, const OSSL_PARAM params[])
{
    UCI_SKEYMGMT *skeymgmt = NULL;
    UCI_SKEY *ret = NULL;

    if (ctx == NULL || key_type == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (mgmt != NULL) {
        skeymgmt = mgmt;
    } else {
        skeymgmt = uci_skeymgmt_fetch_from_prov(ctx->meth->prov,
                                                key_type, propquery);
        if (skeymgmt == NULL) {
            /*
             * The provider does not support skeymgmt, let's try to fallback
             * to a provider that supports it
             */
            skeymgmt = UCI_SKEYMGMT_fetch(ossl_provider_libctx(ctx->meth->prov),
                                          key_type, propquery);
        }

        if (skeymgmt == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED);
            return NULL;
        }
    }

    /* Fallback to raw derive + import if necessary */
    if (skeymgmt->prov != ctx->meth->prov ||
        ctx->meth->derive_skey == NULL) {
        unsigned char *key = NULL;
        OSSL_PARAM import_params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};

        if (ctx->meth->derive == NULL) {
            ERR_raise(ERR_R_UCI_LIB, ERR_R_UNSUPPORTED);
            return NULL;
        }

        key = OPENSSL_zalloc(keylen);
        if (!key)
            return NULL;

        if (!ctx->meth->derive(ctx->algctx, key, keylen, params)) {
            OPENSSL_free(key);
            return NULL;
        }
        import_params[0] = OSSL_PARAM_construct_octet_string(OSSL_SKEY_PARAM_RAW_BYTES,
                                                             key, keylen);

        ret = UCI_SKEY_import_SKEYMGMT(ossl_provider_libctx(ctx->meth->prov), skeymgmt,
                                       OSSL_SKEYMGMT_SELECT_SECRET_KEY, import_params);

        if (mgmt != skeymgmt)
            UCI_SKEYMGMT_free(skeymgmt);

        OPENSSL_clear_free(key, keylen);
        return ret;
    }

    ret = uci_skey_alloc(skeymgmt);
    if (ret == NULL) {
        if (mgmt != skeymgmt)
            UCI_SKEYMGMT_free(skeymgmt);
        return NULL;
    }

    ret->keydata = ctx->meth->derive_skey(ctx->algctx, key_type, ossl_provider_ctx(skeymgmt->prov),
                                          skeymgmt->import, keylen, params);
    if (ret->keydata == NULL) {
        UCI_SKEY_free(ret);
        ret = NULL;
    }

    if (mgmt != skeymgmt)
        UCI_SKEYMGMT_free(skeymgmt);
    return ret;
}

/*
 * The {get,set}_params functions return 1 if there is no corresponding
 * function in the implementation.  This is the same as if there was one,
 * but it didn't recognise any of the given params, i.e. nothing in the
 * bag of parameters was useful.
 */
int UCI_KDF_get_params(UCI_KDF *kdf, OSSL_PARAM params[])
{
    if (kdf->get_params != NULL)
        return kdf->get_params(params);
    return 1;
}

int UCI_KDF_CTX_get_params(UCI_KDF_CTX *ctx, OSSL_PARAM params[])
{
    if (ctx->meth->get_ctx_params != NULL)
        return ctx->meth->get_ctx_params(ctx->algctx, params);
    return 1;
}

int UCI_KDF_CTX_set_params(UCI_KDF_CTX *ctx, const OSSL_PARAM params[])
{
    if (ctx->meth->set_ctx_params != NULL)
        return ctx->meth->set_ctx_params(ctx->algctx, params);
    return 1;
}

int UCI_KDF_names_do_all(const UCI_KDF *kdf,
                         void (*fn)(const char *name, void *data),
                         void *data)
{
    if (kdf->prov != NULL)
        return uci_names_do_all(kdf->prov, kdf->name_id, fn, data);

    return 1;
}
