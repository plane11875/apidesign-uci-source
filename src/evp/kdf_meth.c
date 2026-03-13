/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/kdf.h>
#include "internal/provider.h"
#include "internal/core.h"
#include "crypto/evp.h"
#include "uci_local.h"

static int uci_kdf_up_ref(void *vkdf)
{
    UCI_KDF *kdf = (UCI_KDF *)vkdf;
    int ref = 0;

    CRYPTO_UP_REF(&kdf->refcnt, &ref);
    return 1;
}

static void uci_kdf_free(void *vkdf)
{
    UCI_KDF *kdf = (UCI_KDF *)vkdf;
    int ref = 0;

    if (kdf == NULL)
        return;

    CRYPTO_DOWN_REF(&kdf->refcnt, &ref);
    if (ref > 0)
        return;
    OPENSSL_free(kdf->type_name);
    ossl_provider_free(kdf->prov);
    CRYPTO_FREE_REF(&kdf->refcnt);
    OPENSSL_free(kdf);
}

static void *uci_kdf_new(void)
{
    UCI_KDF *kdf = NULL;

    if ((kdf = OPENSSL_zalloc(sizeof(*kdf))) == NULL
        || !CRYPTO_NEW_REF(&kdf->refcnt, 1)) {
        OPENSSL_free(kdf);
        return NULL;
    }
    return kdf;
}

static void *uci_kdf_from_algorithm(int name_id,
                                    const OSSL_ALGORITHM *algodef,
                                    OSSL_PROVIDER *prov)
{
    const OSSL_DISPATCH *fns = algodef->implementation;
    UCI_KDF *kdf = NULL;
    int fnkdfcnt = 0, fnctxcnt = 0;

    if ((kdf = uci_kdf_new()) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_UCI_LIB);
        return NULL;
    }
    kdf->name_id = name_id;
    if ((kdf->type_name = ossl_algorithm_get1_first_name(algodef)) == NULL)
        goto err;

    kdf->description = algodef->algorithm_description;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KDF_NEWCTX:
            if (kdf->newctx != NULL)
                break;
            kdf->newctx = OSSL_FUNC_kdf_newctx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_KDF_DUPCTX:
            if (kdf->dupctx != NULL)
                break;
            kdf->dupctx = OSSL_FUNC_kdf_dupctx(fns);
            break;
        case OSSL_FUNC_KDF_FREECTX:
            if (kdf->freectx != NULL)
                break;
            kdf->freectx = OSSL_FUNC_kdf_freectx(fns);
            fnctxcnt++;
            break;
        case OSSL_FUNC_KDF_RESET:
            if (kdf->reset != NULL)
                break;
            kdf->reset = OSSL_FUNC_kdf_reset(fns);
            break;
        case OSSL_FUNC_KDF_DERIVE:
            if (kdf->derive != NULL)
                break;
            kdf->derive = OSSL_FUNC_kdf_derive(fns);
            fnkdfcnt++;
            break;
        case OSSL_FUNC_KDF_GETTABLE_PARAMS:
            if (kdf->gettable_params != NULL)
                break;
            kdf->gettable_params =
                OSSL_FUNC_kdf_gettable_params(fns);
            break;
        case OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS:
            if (kdf->gettable_ctx_params != NULL)
                break;
            kdf->gettable_ctx_params =
                OSSL_FUNC_kdf_gettable_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS:
            if (kdf->settable_ctx_params != NULL)
                break;
            kdf->settable_ctx_params =
                OSSL_FUNC_kdf_settable_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_GET_PARAMS:
            if (kdf->get_params != NULL)
                break;
            kdf->get_params = OSSL_FUNC_kdf_get_params(fns);
            break;
        case OSSL_FUNC_KDF_GET_CTX_PARAMS:
            if (kdf->get_ctx_params != NULL)
                break;
            kdf->get_ctx_params = OSSL_FUNC_kdf_get_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_SET_CTX_PARAMS:
            if (kdf->set_ctx_params != NULL)
                break;
            kdf->set_ctx_params = OSSL_FUNC_kdf_set_ctx_params(fns);
            break;
        case OSSL_FUNC_KDF_SET_SKEY:
            if (kdf->set_skey != NULL)
                break;
            kdf->set_skey = OSSL_FUNC_kdf_set_skey(fns);
            break;
        case OSSL_FUNC_KDF_DERIVE_SKEY:
            if (kdf->derive_skey != NULL)
                break;
            kdf->derive_skey = OSSL_FUNC_kdf_derive_skey(fns);
            break;
        }
    }
    if (fnkdfcnt != 1 || fnctxcnt != 2) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a derive function, and a complete set of context management
         * functions.
         */
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_PROVIDER_FUNCTIONS);
        goto err;
    }
    if (prov != NULL && !ossl_provider_up_ref(prov))
        goto err;

    kdf->prov = prov;

    return kdf;

err:
    uci_kdf_free(kdf);
    return NULL;
}

UCI_KDF *UCI_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
                       const char *properties)
{
    return uci_generic_fetch(libctx, OSSL_OP_KDF, algorithm, properties,
                             uci_kdf_from_algorithm, uci_kdf_up_ref,
                             uci_kdf_free);
}

int UCI_KDF_up_ref(UCI_KDF *kdf)
{
    return uci_kdf_up_ref(kdf);
}

void UCI_KDF_free(UCI_KDF *kdf)
{
    uci_kdf_free(kdf);
}

const OSSL_PARAM *UCI_KDF_gettable_params(const UCI_KDF *kdf)
{
    if (kdf->gettable_params == NULL)
        return NULL;
    return kdf->gettable_params(ossl_provider_ctx(UCI_KDF_get0_provider(kdf)));
}

const OSSL_PARAM *UCI_KDF_gettable_ctx_params(const UCI_KDF *kdf)
{
    void *alg;

    if (kdf->gettable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(UCI_KDF_get0_provider(kdf));
    return kdf->gettable_ctx_params(NULL, alg);
}

const OSSL_PARAM *UCI_KDF_settable_ctx_params(const UCI_KDF *kdf)
{
    void *alg;

    if (kdf->settable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(UCI_KDF_get0_provider(kdf));
    return kdf->settable_ctx_params(NULL, alg);
}

const OSSL_PARAM *UCI_KDF_CTX_gettable_params(UCI_KDF_CTX *ctx)
{
    void *alg;

    if (ctx->meth->gettable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(UCI_KDF_get0_provider(ctx->meth));
    return ctx->meth->gettable_ctx_params(ctx->algctx, alg);
}

const OSSL_PARAM *UCI_KDF_CTX_settable_params(UCI_KDF_CTX *ctx)
{
    void *alg;

    if (ctx->meth->settable_ctx_params == NULL)
        return NULL;
    alg = ossl_provider_ctx(UCI_KDF_get0_provider(ctx->meth));
    return ctx->meth->settable_ctx_params(ctx->algctx, alg);
}

void UCI_KDF_do_all_provided(OSSL_LIB_CTX *libctx,
                             void (*fn)(UCI_KDF *kdf, void *arg),
                             void *arg)
{
    uci_generic_do_all(libctx, OSSL_OP_KDF,
                       (void (*)(void *, void *))fn, arg,
                       uci_kdf_from_algorithm, uci_kdf_up_ref, uci_kdf_free);
}
