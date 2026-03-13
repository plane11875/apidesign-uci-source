/*
 * Copyright 2020-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/provider.h"
#include "internal/core.h"
#include "crypto/evp.h"
#include "uci_local.h"

static void uci_kem_free(void *data)
{
    UCI_KEM_free(data);
}

static int uci_kem_up_ref(void *data)
{
    return UCI_KEM_up_ref(data);
}

static int uci_kem_init(UCI_PKEY_CTX *ctx, int operation,
                        const OSSL_PARAM params[], UCI_PKEY *authkey)
{
    int ret = 0;
    UCI_KEM *kem = NULL;
    UCI_KEYMGMT *tmp_keymgmt = NULL;
    const OSSL_PROVIDER *tmp_prov = NULL;
    void *provkey = NULL, *provauthkey = NULL;
    const char *supported_kem = NULL;
    int iter;

    if (ctx == NULL || ctx->keytype == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
        return 0;
    }

    uci_pkey_ctx_free_old_ops(ctx);
    ctx->operation = operation;

    if (ctx->pkey == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_NO_KEY_SET);
        goto err;
    }
    if (authkey != NULL && authkey->type != ctx->pkey->type) {
        ERR_raise(ERR_LIB_EVP, UCI_R_DIFFERENT_KEY_TYPES);
        return 0;
    }
    /*
     * Try to derive the supported kem from |ctx->keymgmt|.
     */
    if (!ossl_assert(ctx->pkey->keymgmt == NULL
                     || ctx->pkey->keymgmt == ctx->keymgmt)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    supported_kem = uci_keymgmt_util_query_operation_name(ctx->keymgmt,
                                                          OSSL_OP_KEM);
    if (supported_kem == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
        goto err;
    }

    /*
     * Because we cleared out old ops, we shouldn't need to worry about
     * checking if kem is already there.
     * We perform two iterations:
     *
     * 1.  Do the normal kem fetch, using the fetching data given by
     *     the UCI_PKEY_CTX.
     * 2.  Do the provider specific kem fetch, from the same provider
     *     as |ctx->keymgmt|
     *
     * We then try to fetch the keymgmt from the same provider as the
     * kem, and try to export |ctx->pkey| to that keymgmt (when this
     * keymgmt happens to be the same as |ctx->keymgmt|, the export is
     * a no-op, but we call it anyway to not complicate the code even
     * more).
     * If the export call succeeds (returns a non-NULL provider key pointer),
     * we're done and can perform the operation itself.  If not, we perform
     * the second iteration, or jump to legacy.
     */
    for (iter = 1, provkey = NULL; iter < 3 && provkey == NULL; iter++) {
        UCI_KEYMGMT *tmp_keymgmt_tofree = NULL;

        /*
         * If we're on the second iteration, free the results from the first.
         * They are NULL on the first iteration, so no need to check what
         * iteration we're on.
         */
        UCI_KEM_free(kem);
        UCI_KEYMGMT_free(tmp_keymgmt);

        switch (iter) {
        case 1:
            kem = UCI_KEM_fetch(ctx->libctx, supported_kem, ctx->propquery);
            if (kem != NULL)
                tmp_prov = UCI_KEM_get0_provider(kem);
            break;
        case 2:
            tmp_prov = UCI_KEYMGMT_get0_provider(ctx->keymgmt);
            kem = uci_kem_fetch_from_prov((OSSL_PROVIDER *)tmp_prov,
                                          supported_kem, ctx->propquery);

            if (kem == NULL) {
                ERR_raise(ERR_LIB_EVP,
                          UCI_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
                ret = -2;
                goto err;
            }
        }
        if (kem == NULL)
            continue;

        /*
         * Ensure that the key is provided, either natively, or as a cached
         * export.  We start by fetching the keymgmt with the same name as
         * |ctx->pkey|, but from the provider of the kem method, using the
         * same property query as when fetching the kem method.
         * With the keymgmt we found (if we did), we try to export |ctx->pkey|
         * to it (uci_pkey_export_to_provider() is smart enough to only actually
         * export it if |tmp_keymgmt| is different from |ctx->pkey|'s keymgmt)
         */
        tmp_keymgmt_tofree = tmp_keymgmt =
            uci_keymgmt_fetch_from_prov((OSSL_PROVIDER *)tmp_prov,
                                        UCI_KEYMGMT_get0_name(ctx->keymgmt),
                                        ctx->propquery);
        if (tmp_keymgmt != NULL) {
            provkey = uci_pkey_export_to_provider(ctx->pkey, ctx->libctx,
                                                  &tmp_keymgmt, ctx->propquery);
            if (provkey != NULL && authkey != NULL) {
                provauthkey = uci_pkey_export_to_provider(authkey, ctx->libctx,
                                                          &tmp_keymgmt,
                                                          ctx->propquery);
                if (provauthkey == NULL) {
                    UCI_KEM_free(kem);
                    ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
                    goto err;
                }
            }
        }
        if (tmp_keymgmt == NULL)
            UCI_KEYMGMT_free(tmp_keymgmt_tofree);
    }

    if (provkey == NULL) {
        UCI_KEM_free(kem);
        ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
        goto err;
    }

    ctx->op.encap.kem = kem;
    ctx->op.encap.algctx = kem->newctx(ossl_provider_ctx(kem->prov));
    if (ctx->op.encap.algctx == NULL) {
        /* The provider key can stay in the cache */
        ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
        goto err;
    }

    switch (operation) {
    case UCI_PKEY_OP_ENCAPSULATE:
        if (provauthkey != NULL && kem->auth_encapsulate_init != NULL) {
            ret = kem->auth_encapsulate_init(ctx->op.encap.algctx, provkey,
                                             provauthkey, params);
        } else if (provauthkey == NULL && kem->encapsulate_init != NULL) {
            ret = kem->encapsulate_init(ctx->op.encap.algctx, provkey, params);
        } else {
            ERR_raise(ERR_LIB_EVP, UCI_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            ret = -2;
            goto err;
        }
        break;
    case UCI_PKEY_OP_DECAPSULATE:
        if (provauthkey != NULL && kem->auth_decapsulate_init != NULL) {
            ret = kem->auth_decapsulate_init(ctx->op.encap.algctx, provkey,
                                             provauthkey, params);
        } else if (provauthkey == NULL && kem->encapsulate_init != NULL) {
            ret = kem->decapsulate_init(ctx->op.encap.algctx, provkey, params);
        } else {
            ERR_raise(ERR_LIB_EVP, UCI_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
            ret = -2;
            goto err;
        }
        break;
    default:
        ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
        goto err;
    }

    UCI_KEYMGMT_free(tmp_keymgmt);
    tmp_keymgmt = NULL;

    if (ret > 0)
        return 1;
 err:
    if (ret <= 0) {
        uci_pkey_ctx_free_old_ops(ctx);
        ctx->operation = UCI_PKEY_OP_UNDEFINED;
    }
    UCI_KEYMGMT_free(tmp_keymgmt);
    return ret;
}

int UCI_PKEY_auth_encapsulate_init(UCI_PKEY_CTX *ctx, UCI_PKEY *authpriv,
                                   const OSSL_PARAM params[])
{
    if (authpriv == NULL)
        return 0;
    return uci_kem_init(ctx, UCI_PKEY_OP_ENCAPSULATE, params, authpriv);
}

int UCI_PKEY_encapsulate_init(UCI_PKEY_CTX *ctx, const OSSL_PARAM params[])
{
    return uci_kem_init(ctx, UCI_PKEY_OP_ENCAPSULATE, params, NULL);
}

int UCI_PKEY_encapsulate(UCI_PKEY_CTX *ctx,
                         unsigned char *out, size_t *outlen,
                         unsigned char *secret, size_t *secretlen)
{
    if (ctx == NULL)
        return 0;

    if (ctx->operation != UCI_PKEY_OP_ENCAPSULATE) {
        ERR_raise(ERR_LIB_EVP, UCI_R_OPERATION_NOT_INITIALIZED);
        return -1;
    }

    if (ctx->op.encap.algctx == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }

    if (out != NULL && secret == NULL)
        return 0;

    return ctx->op.encap.kem->encapsulate(ctx->op.encap.algctx,
                                          out, outlen, secret, secretlen);
}

int UCI_PKEY_decapsulate_init(UCI_PKEY_CTX *ctx, const OSSL_PARAM params[])
{
    return uci_kem_init(ctx, UCI_PKEY_OP_DECAPSULATE, params, NULL);
}

int UCI_PKEY_auth_decapsulate_init(UCI_PKEY_CTX *ctx, UCI_PKEY *authpub,
                                   const OSSL_PARAM params[])
{
    if (authpub == NULL)
        return 0;
    return uci_kem_init(ctx, UCI_PKEY_OP_DECAPSULATE, params, authpub);
}

int UCI_PKEY_decapsulate(UCI_PKEY_CTX *ctx,
                         unsigned char *secret, size_t *secretlen,
                         const unsigned char *in, size_t inlen)
{
    if (ctx == NULL
        || (in == NULL || inlen == 0)
        || (secret == NULL && secretlen == NULL))
        return 0;

    if (ctx->operation != UCI_PKEY_OP_DECAPSULATE) {
        ERR_raise(ERR_LIB_EVP, UCI_R_OPERATION_NOT_INITIALIZED);
        return -1;
    }

    if (ctx->op.encap.algctx == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
        return -2;
    }
    return ctx->op.encap.kem->decapsulate(ctx->op.encap.algctx,
                                          secret, secretlen, in, inlen);
}

static UCI_KEM *uci_kem_new(OSSL_PROVIDER *prov)
{
    UCI_KEM *kem = OPENSSL_zalloc(sizeof(UCI_KEM));

    if (kem == NULL)
        return NULL;

    if (!CRYPTO_NEW_REF(&kem->refcnt, 1)
        || !ossl_provider_up_ref(prov)) {
        CRYPTO_FREE_REF(&kem->refcnt);
        OPENSSL_free(kem);
        return NULL;
    }
    kem->prov = prov;

    return kem;
}

static void *uci_kem_from_algorithm(int name_id, const OSSL_ALGORITHM *algodef,
                                    OSSL_PROVIDER *prov)
{
    const OSSL_DISPATCH *fns = algodef->implementation;
    UCI_KEM *kem = NULL;
    int ctxfncnt = 0, encfncnt = 0, decfncnt = 0;
    int gparamfncnt = 0, sparamfncnt = 0;

    if ((kem = uci_kem_new(prov)) == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_UCI_LIB);
        goto err;
    }

    kem->name_id = name_id;
    if ((kem->type_name = ossl_algorithm_get1_first_name(algodef)) == NULL)
        goto err;
    kem->description = algodef->algorithm_description;

    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_KEM_NEWCTX:
            if (kem->newctx != NULL)
                break;
            kem->newctx = OSSL_FUNC_kem_newctx(fns);
            ctxfncnt++;
            break;
        case OSSL_FUNC_KEM_ENCAPSULATE_INIT:
            if (kem->encapsulate_init != NULL)
                break;
            kem->encapsulate_init = OSSL_FUNC_kem_encapsulate_init(fns);
            encfncnt++;
            break;
        case OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT:
            if (kem->auth_encapsulate_init != NULL)
                break;
            kem->auth_encapsulate_init = OSSL_FUNC_kem_auth_encapsulate_init(fns);
            encfncnt++;
            break;
        case OSSL_FUNC_KEM_ENCAPSULATE:
            if (kem->encapsulate != NULL)
                break;
            kem->encapsulate = OSSL_FUNC_kem_encapsulate(fns);
            encfncnt++;
            break;
        case OSSL_FUNC_KEM_DECAPSULATE_INIT:
            if (kem->decapsulate_init != NULL)
                break;
            kem->decapsulate_init = OSSL_FUNC_kem_decapsulate_init(fns);
            decfncnt++;
            break;
        case OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT:
            if (kem->auth_decapsulate_init != NULL)
                break;
            kem->auth_decapsulate_init = OSSL_FUNC_kem_auth_decapsulate_init(fns);
            decfncnt++;
            break;
        case OSSL_FUNC_KEM_DECAPSULATE:
            if (kem->decapsulate != NULL)
                break;
            kem->decapsulate = OSSL_FUNC_kem_decapsulate(fns);
            decfncnt++;
            break;
        case OSSL_FUNC_KEM_FREECTX:
            if (kem->freectx != NULL)
                break;
            kem->freectx = OSSL_FUNC_kem_freectx(fns);
            ctxfncnt++;
            break;
        case OSSL_FUNC_KEM_DUPCTX:
            if (kem->dupctx != NULL)
                break;
            kem->dupctx = OSSL_FUNC_kem_dupctx(fns);
            break;
        case OSSL_FUNC_KEM_GET_CTX_PARAMS:
            if (kem->get_ctx_params != NULL)
                break;
            kem->get_ctx_params
                = OSSL_FUNC_kem_get_ctx_params(fns);
            gparamfncnt++;
            break;
        case OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS:
            if (kem->gettable_ctx_params != NULL)
                break;
            kem->gettable_ctx_params
                = OSSL_FUNC_kem_gettable_ctx_params(fns);
            gparamfncnt++;
            break;
        case OSSL_FUNC_KEM_SET_CTX_PARAMS:
            if (kem->set_ctx_params != NULL)
                break;
            kem->set_ctx_params
                = OSSL_FUNC_kem_set_ctx_params(fns);
            sparamfncnt++;
            break;
        case OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS:
            if (kem->settable_ctx_params != NULL)
                break;
            kem->settable_ctx_params
                = OSSL_FUNC_kem_settable_ctx_params(fns);
            sparamfncnt++;
            break;
        }
    }
    if (ctxfncnt != 2
        || (encfncnt != 0 && encfncnt != 2 && encfncnt != 3)
        || (decfncnt != 0 && decfncnt != 2 && decfncnt != 3)
        || (encfncnt != decfncnt)
        || (gparamfncnt != 0 && gparamfncnt != 2)
        || (sparamfncnt != 0 && sparamfncnt != 2)) {
        /*
         * In order to be a consistent set of functions we must have at least
         * a set of context functions (newctx and freectx) as well as a pair
         * (or triplet) of "kem" functions:
         * (encapsulate_init, (and/or auth_encapsulate_init), encapsulate) or
         * (decapsulate_init, (and/or auth_decapsulate_init), decapsulate).
         * set_ctx_params and settable_ctx_params are optional, but if one of
         * them is present then the other one must also be present. The same
         * applies to get_ctx_params and gettable_ctx_params.
         * The dupctx function is optional.
         */
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_PROVIDER_FUNCTIONS);
        goto err;
    }

    return kem;
 err:
    UCI_KEM_free(kem);
    return NULL;
}

void UCI_KEM_free(UCI_KEM *kem)
{
    int i;

    if (kem == NULL)
        return;

    CRYPTO_DOWN_REF(&kem->refcnt, &i);
    if (i > 0)
        return;
    OPENSSL_free(kem->type_name);
    ossl_provider_free(kem->prov);
    CRYPTO_FREE_REF(&kem->refcnt);
    OPENSSL_free(kem);
}

int UCI_KEM_up_ref(UCI_KEM *kem)
{
    int ref = 0;

    CRYPTO_UP_REF(&kem->refcnt, &ref);
    return 1;
}

OSSL_PROVIDER *UCI_KEM_get0_provider(const UCI_KEM *kem)
{
    return kem->prov;
}

UCI_KEM *UCI_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
                       const char *properties)
{
    return uci_generic_fetch(ctx, OSSL_OP_KEM, algorithm, properties,
                             uci_kem_from_algorithm,
                             uci_kem_up_ref,
                             uci_kem_free);
}

UCI_KEM *uci_kem_fetch_from_prov(OSSL_PROVIDER *prov, const char *algorithm,
                                 const char *properties)
{
    return uci_generic_fetch_from_prov(prov, OSSL_OP_KEM, algorithm, properties,
                                       uci_kem_from_algorithm,
                                       uci_kem_up_ref,
                                       uci_kem_free);
}

int UCI_KEM_is_a(const UCI_KEM *kem, const char *name)
{
    return kem != NULL && uci_is_a(kem->prov, kem->name_id, NULL, name);
}

int uci_kem_get_number(const UCI_KEM *kem)
{
    return kem->name_id;
}

const char *UCI_KEM_get0_name(const UCI_KEM *kem)
{
    return kem->type_name;
}

const char *UCI_KEM_get0_description(const UCI_KEM *kem)
{
    return kem->description;
}

void UCI_KEM_do_all_provided(OSSL_LIB_CTX *libctx,
                             void (*fn)(UCI_KEM *kem, void *arg),
                             void *arg)
{
    uci_generic_do_all(libctx, OSSL_OP_KEM, (void (*)(void *, void *))fn, arg,
                       uci_kem_from_algorithm,
                       uci_kem_up_ref,
                       uci_kem_free);
}

int UCI_KEM_names_do_all(const UCI_KEM *kem,
                         void (*fn)(const char *name, void *data),
                         void *data)
{
    if (kem->prov != NULL)
        return uci_names_do_all(kem->prov, kem->name_id, fn, data);

    return 1;
}

const OSSL_PARAM *UCI_KEM_gettable_ctx_params(const UCI_KEM *kem)
{
    void *provctx;

    if (kem == NULL || kem->gettable_ctx_params == NULL)
        return NULL;

    provctx = ossl_provider_ctx(UCI_KEM_get0_provider(kem));
    return kem->gettable_ctx_params(NULL, provctx);
}

const OSSL_PARAM *UCI_KEM_settable_ctx_params(const UCI_KEM *kem)
{
    void *provctx;

    if (kem == NULL || kem->settable_ctx_params == NULL)
        return NULL;

    provctx = ossl_provider_ctx(UCI_KEM_get0_provider(kem));
    return kem->settable_ctx_params(NULL, provctx);
}
