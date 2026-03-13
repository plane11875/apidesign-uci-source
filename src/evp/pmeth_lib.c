/*
 * Copyright 2006-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low level key APIs (DH etc) are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <stdlib.h>
#ifndef FIPS_MODULE
# include <openssl/engine.h>
#endif
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/kdf.h>
#include "internal/cryptlib.h"
#ifndef FIPS_MODULE
# include "crypto/asn1.h"
#endif
#include "crypto/evp.h"
#include "crypto/dh.h"
#include "crypto/ec.h"
#include "internal/ffc.h"
#include "internal/numbers.h"
#include "internal/provider.h"
#include "uci_local.h"

#ifndef FIPS_MODULE

static int uci_pkey_ctx_store_cached_data(UCI_PKEY_CTX *ctx,
                                          int keytype, int optype,
                                          int cmd, const char *name,
                                          const void *data, size_t data_len);
static void uci_pkey_ctx_free_cached_data(UCI_PKEY_CTX *ctx,
                                          int cmd, const char *name);
static void uci_pkey_ctx_free_all_cached_data(UCI_PKEY_CTX *ctx);

typedef const UCI_PKEY_METHOD *(*pmeth_fn)(void);
typedef int sk_cmp_fn_type(const char *const *a, const char *const *b);

static STACK_OF(UCI_PKEY_METHOD) *app_pkey_methods = NULL;

/* This array needs to be in order of NIDs */
static pmeth_fn standard_methods[] = {
    ossl_rsa_pkey_method,
# ifndef OPENSSL_NO_DH
    ossl_dh_pkey_method,
# endif
# ifndef OPENSSL_NO_DSA
    ossl_dsa_pkey_method,
# endif
# ifndef OPENSSL_NO_EC
    ossl_ec_pkey_method,
# endif
    ossl_rsa_pss_pkey_method,
# ifndef OPENSSL_NO_DH
    ossl_dhx_pkey_method,
# endif
# ifndef OPENSSL_NO_ECX
    ossl_ecx25519_pkey_method,
    ossl_ecx448_pkey_method,
    ossl_ed25519_pkey_method,
    ossl_ed448_pkey_method,
# endif
};

DECLARE_OBJ_BSEARCH_CMP_FN(const UCI_PKEY_METHOD *, pmeth_fn, pmeth_func);

static int pmeth_func_cmp(const UCI_PKEY_METHOD *const *a, pmeth_fn const *b)
{
    return ((*a)->pkey_id - ((**b)())->pkey_id);
}

IMPLEMENT_OBJ_BSEARCH_CMP_FN(const UCI_PKEY_METHOD *, pmeth_fn, pmeth_func);

static int pmeth_cmp(const UCI_PKEY_METHOD *const *a,
                     const UCI_PKEY_METHOD *const *b)
{
    return ((*a)->pkey_id - (*b)->pkey_id);
}

static const UCI_PKEY_METHOD *uci_pkey_meth_find_added_by_application(int type)
{
    if (app_pkey_methods != NULL) {
        int idx;
        UCI_PKEY_METHOD tmp;

        tmp.pkey_id = type;
        idx = sk_UCI_PKEY_METHOD_find(app_pkey_methods, &tmp);
        if (idx >= 0)
            return sk_UCI_PKEY_METHOD_value(app_pkey_methods, idx);
    }
    return NULL;
}

const UCI_PKEY_METHOD *UCI_PKEY_meth_find(int type)
{
    pmeth_fn *ret;
    UCI_PKEY_METHOD tmp;
    const UCI_PKEY_METHOD *t;

    if ((t = uci_pkey_meth_find_added_by_application(type)) != NULL)
        return t;

    tmp.pkey_id = type;
    t = &tmp;
    ret = OBJ_bsearch_pmeth_func(&t, standard_methods,
                                 OSSL_NELEM(standard_methods));
    if (ret == NULL || *ret == NULL)
        return NULL;
    return (**ret)();
}

UCI_PKEY_METHOD *UCI_PKEY_meth_new(int id, int flags)
{
    UCI_PKEY_METHOD *pmeth;

    pmeth = OPENSSL_zalloc(sizeof(*pmeth));
    if (pmeth == NULL)
        return NULL;

    pmeth->pkey_id = id;
    pmeth->flags = flags | UCI_PKEY_FLAG_DYNAMIC;
    return pmeth;
}
#endif /* FIPS_MODULE */

int uci_pkey_ctx_state(const UCI_PKEY_CTX *ctx)
{
    if (ctx->operation == UCI_PKEY_OP_UNDEFINED)
        return UCI_PKEY_STATE_UNKNOWN;

    if ((UCI_PKEY_CTX_IS_DERIVE_OP(ctx)
         && ctx->op.kex.algctx != NULL)
        || (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.algctx != NULL)
        || (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            && ctx->op.ciph.algctx != NULL)
        || (UCI_PKEY_CTX_IS_GEN_OP(ctx)
            && ctx->op.keymgmt.genctx != NULL)
        || (UCI_PKEY_CTX_IS_KEM_OP(ctx)
            && ctx->op.encap.algctx != NULL))
        return UCI_PKEY_STATE_PROVIDER;

    return UCI_PKEY_STATE_LEGACY;
}

static UCI_PKEY_CTX *int_ctx_new(OSSL_LIB_CTX *libctx,
                                 UCI_PKEY *pkey, ENGINE *e,
                                 const char *keytype, const char *propquery,
                                 int id)

{
    UCI_PKEY_CTX *ret = NULL;
    const UCI_PKEY_METHOD *pmeth = NULL, *app_pmeth = NULL;
    UCI_KEYMGMT *keymgmt = NULL;

    /* Code below to be removed when legacy support is dropped. */
    /* BEGIN legacy */
    if (id == -1) {
        if (pkey != NULL && !uci_pkey_is_provided(pkey)) {
            id = pkey->type;
        } else {
            if (pkey != NULL) {
                /* Must be provided if we get here */
                keytype = UCI_KEYMGMT_get0_name(pkey->keymgmt);
            }
#ifndef FIPS_MODULE
            if (keytype != NULL) {
                id = uci_pkey_name2type(keytype);
                if (id == NID_undef)
                    id = -1;
            }
#endif
        }
    }
    /* If no ID was found here, we can only resort to find a keymgmt */
    if (id == -1) {
#ifndef FIPS_MODULE
        /* Using engine with a key without id will not work */
        if (e != NULL) {
            ERR_raise(ERR_LIB_EVP, UCI_R_UNSUPPORTED_ALGORITHM);
            return NULL;
        }
#endif
        goto common;
    }

#ifndef FIPS_MODULE
    /*
     * Here, we extract what information we can for the purpose of
     * supporting usage with implementations from providers, to make
     * for a smooth transition from legacy stuff to provider based stuff.
     *
     * If an engine is given, this is entirely legacy, and we should not
     * pretend anything else, so we clear the name.
     */
    if (e != NULL)
        keytype = NULL;
    if (e == NULL && (pkey == NULL || pkey->foreign == 0))
        keytype = OBJ_nid2sn(id);

# ifndef OPENSSL_NO_ENGINE
    if (e == NULL && pkey != NULL)
        e = pkey->pmeth_engine != NULL ? pkey->pmeth_engine : pkey->engine;
    /* Try to find an ENGINE which implements this method */
    if (e != NULL) {
        if (!ENGINE_init(e)) {
            ERR_raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB);
            return NULL;
        }
    } else {
        e = ENGINE_get_pkey_meth_engine(id);
    }

    /*
     * If an ENGINE handled this method look it up. Otherwise use internal
     * tables.
     */
    if (e != NULL)
        pmeth = ENGINE_get_pkey_meth(e, id);
    else
# endif /* OPENSSL_NO_ENGINE */
    if (pkey != NULL && pkey->foreign)
        pmeth = UCI_PKEY_meth_find(id);
    else
        app_pmeth = pmeth = uci_pkey_meth_find_added_by_application(id);

    /* END legacy */
#endif /* FIPS_MODULE */
 common:
    /*
     * If there's no engine and no app supplied pmeth and there's a name, we try
     * fetching a provider implementation.
     */
    if (e == NULL && app_pmeth == NULL && keytype != NULL) {
        /*
         * If |pkey| is given and is provided, we take a reference to its
         * keymgmt.  Otherwise, we fetch one for the keytype we got. This
         * is to ensure that operation init functions can access what they
         * need through this single pointer.
         */
        if (pkey != NULL && pkey->keymgmt != NULL) {
            if (!UCI_KEYMGMT_up_ref(pkey->keymgmt))
                ERR_raise(ERR_LIB_EVP, UCI_R_INITIALIZATION_ERROR);
            else
                keymgmt = pkey->keymgmt;
        } else {
            keymgmt = UCI_KEYMGMT_fetch(libctx, keytype, propquery);
        }
        if (keymgmt == NULL)
            return NULL;   /* UCI_KEYMGMT_fetch() recorded an error */

#ifndef FIPS_MODULE
        /*
         * Chase down the legacy NID, as that might be needed for diverse
         * purposes, such as ensure that UCI_PKEY_type() can return sensible
         * values. We go through all keymgmt names, because the keytype
         * that's passed to this function doesn't necessarily translate
         * directly.
         */
        if (keymgmt != NULL) {
            int tmp_id = uci_keymgmt_get_legacy_alg(keymgmt);

            if (tmp_id != NID_undef) {
                if (id == -1) {
                    id = tmp_id;
                } else {
                    /*
                     * It really really shouldn't differ.  If it still does,
                     * something is very wrong.
                     */
                    if (!ossl_assert(id == tmp_id)) {
                        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
                        UCI_KEYMGMT_free(keymgmt);
                        return NULL;
                    }
                }
            }
        }
#endif
    }

    if (pmeth == NULL && keymgmt == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_UNSUPPORTED_ALGORITHM);
    } else {
        ret = OPENSSL_zalloc(sizeof(*ret));
    }

#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)
    if ((ret == NULL || pmeth == NULL) && e != NULL)
        ENGINE_finish(e);
#endif

    if (ret == NULL) {
        UCI_KEYMGMT_free(keymgmt);
        return NULL;
    }
    if (propquery != NULL) {
        ret->propquery = OPENSSL_strdup(propquery);
        if (ret->propquery == NULL) {
            OPENSSL_free(ret);
            UCI_KEYMGMT_free(keymgmt);
            return NULL;
        }
    }
    ret->libctx = libctx;
    ret->keytype = keytype;
    ret->keymgmt = keymgmt;
    ret->legacy_keytype = id;
    ret->engine = e;
    ret->pmeth = pmeth;
    ret->operation = UCI_PKEY_OP_UNDEFINED;

    if (pkey != NULL && !UCI_PKEY_up_ref(pkey)) {
        UCI_PKEY_CTX_free(ret);
        return NULL;
    }

    ret->pkey = pkey;

    if (pmeth != NULL && pmeth->init != NULL) {
        if (pmeth->init(ret) <= 0) {
            ret->pmeth = NULL;
            UCI_PKEY_CTX_free(ret);
            return NULL;
        }
    }

    return ret;
}

/*- All methods below can also be used in FIPS_MODULE */

UCI_PKEY_CTX *UCI_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
                                         const char *name,
                                         const char *propquery)
{
    return int_ctx_new(libctx, NULL, NULL, name, propquery, -1);
}

UCI_PKEY_CTX *UCI_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, UCI_PKEY *pkey,
                                         const char *propquery)
{
    return int_ctx_new(libctx, pkey, NULL, NULL, propquery, -1);
}

void uci_pkey_ctx_free_old_ops(UCI_PKEY_CTX *ctx)
{
    if (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        if (ctx->op.sig.algctx != NULL && ctx->op.sig.signature != NULL)
            ctx->op.sig.signature->freectx(ctx->op.sig.algctx);
        UCI_SIGNATURE_free(ctx->op.sig.signature);
        ctx->op.sig.algctx = NULL;
        ctx->op.sig.signature = NULL;
    } else if (UCI_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        if (ctx->op.kex.algctx != NULL && ctx->op.kex.exchange != NULL)
            ctx->op.kex.exchange->freectx(ctx->op.kex.algctx);
        UCI_KEYEXCH_free(ctx->op.kex.exchange);
        ctx->op.kex.algctx = NULL;
        ctx->op.kex.exchange = NULL;
    } else if (UCI_PKEY_CTX_IS_KEM_OP(ctx)) {
        if (ctx->op.encap.algctx != NULL && ctx->op.encap.kem != NULL)
            ctx->op.encap.kem->freectx(ctx->op.encap.algctx);
        UCI_KEM_free(ctx->op.encap.kem);
        ctx->op.encap.algctx = NULL;
        ctx->op.encap.kem = NULL;
    }
    else if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        if (ctx->op.ciph.algctx != NULL && ctx->op.ciph.cipher != NULL)
            ctx->op.ciph.cipher->freectx(ctx->op.ciph.algctx);
        UCI_ASYM_CIPHER_free(ctx->op.ciph.cipher);
        ctx->op.ciph.algctx = NULL;
        ctx->op.ciph.cipher = NULL;
    } else if (UCI_PKEY_CTX_IS_GEN_OP(ctx)) {
        if (ctx->op.keymgmt.genctx != NULL && ctx->keymgmt != NULL)
            uci_keymgmt_gen_cleanup(ctx->keymgmt, ctx->op.keymgmt.genctx);
    }
}

void UCI_PKEY_CTX_free(UCI_PKEY_CTX *ctx)
{
    if (ctx == NULL)
        return;
    if (ctx->pmeth && ctx->pmeth->cleanup)
        ctx->pmeth->cleanup(ctx);

    uci_pkey_ctx_free_old_ops(ctx);
#ifndef FIPS_MODULE
    uci_pkey_ctx_free_all_cached_data(ctx);
#endif
    UCI_KEYMGMT_free(ctx->keymgmt);

    OPENSSL_free(ctx->propquery);
    UCI_PKEY_free(ctx->pkey);
    UCI_PKEY_free(ctx->peerkey);
#if !defined(OPENSSL_NO_ENGINE) && !defined(FIPS_MODULE)
    ENGINE_finish(ctx->engine);
#endif
    BN_free(ctx->rsa_pubexp);
    OPENSSL_free(ctx);
}

#ifndef FIPS_MODULE

void UCI_PKEY_meth_get0_info(int *ppkey_id, int *pflags,
                             const UCI_PKEY_METHOD *meth)
{
    if (ppkey_id)
        *ppkey_id = meth->pkey_id;
    if (pflags)
        *pflags = meth->flags;
}

void UCI_PKEY_meth_copy(UCI_PKEY_METHOD *dst, const UCI_PKEY_METHOD *src)
{
    int pkey_id = dst->pkey_id;
    int flags = dst->flags;

    *dst = *src;

    /* We only copy the function pointers so restore the other values */
    dst->pkey_id = pkey_id;
    dst->flags = flags;
}

void UCI_PKEY_meth_free(UCI_PKEY_METHOD *pmeth)
{
    if (pmeth && (pmeth->flags & UCI_PKEY_FLAG_DYNAMIC))
        OPENSSL_free(pmeth);
}

UCI_PKEY_CTX *UCI_PKEY_CTX_new(UCI_PKEY *pkey, ENGINE *e)
{
    return int_ctx_new(NULL, pkey, e, NULL, NULL, -1);
}

UCI_PKEY_CTX *UCI_PKEY_CTX_new_id(int id, ENGINE *e)
{
    return int_ctx_new(NULL, NULL, e, NULL, NULL, id);
}

UCI_PKEY_CTX *UCI_PKEY_CTX_dup(const UCI_PKEY_CTX *pctx)
{
    UCI_PKEY_CTX *rctx;

# ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a pkey context using an ENGINE */
    if (pctx->engine && !ENGINE_init(pctx->engine)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB);
        return 0;
    }
# endif
    rctx = OPENSSL_zalloc(sizeof(*rctx));
    if (rctx == NULL)
        return NULL;

    if (pctx->pkey != NULL && !UCI_PKEY_up_ref(pctx->pkey))
        goto err;

    rctx->pkey = pctx->pkey;
    rctx->operation = pctx->operation;
    rctx->libctx = pctx->libctx;
    rctx->keytype = pctx->keytype;
    rctx->propquery = NULL;
    if (pctx->propquery != NULL) {
        rctx->propquery = OPENSSL_strdup(pctx->propquery);
        if (rctx->propquery == NULL)
            goto err;
    }
    rctx->legacy_keytype = pctx->legacy_keytype;

    if (pctx->keymgmt != NULL) {
        if (!UCI_KEYMGMT_up_ref(pctx->keymgmt))
            goto err;
        rctx->keymgmt = pctx->keymgmt;
    }

    if (UCI_PKEY_CTX_IS_DERIVE_OP(pctx)) {
        if (pctx->op.kex.exchange != NULL) {
            rctx->op.kex.exchange = pctx->op.kex.exchange;
            if (!UCI_KEYEXCH_up_ref(rctx->op.kex.exchange))
                goto err;
        }
        if (pctx->op.kex.algctx != NULL) {
            if (!ossl_assert(pctx->op.kex.exchange != NULL))
                goto err;

            if (pctx->op.kex.exchange->dupctx != NULL)
                rctx->op.kex.algctx
                    = pctx->op.kex.exchange->dupctx(pctx->op.kex.algctx);

            if (rctx->op.kex.algctx == NULL) {
                UCI_KEYEXCH_free(rctx->op.kex.exchange);
                rctx->op.kex.exchange = NULL;
                goto err;
            }
            return rctx;
        }
    } else if (UCI_PKEY_CTX_IS_SIGNATURE_OP(pctx)) {
        if (pctx->op.sig.signature != NULL) {
            rctx->op.sig.signature = pctx->op.sig.signature;
            if (!UCI_SIGNATURE_up_ref(rctx->op.sig.signature))
                goto err;
        }
        if (pctx->op.sig.algctx != NULL) {
            if (!ossl_assert(pctx->op.sig.signature != NULL))
                goto err;

            if (pctx->op.sig.signature->dupctx != NULL)
                rctx->op.sig.algctx
                    = pctx->op.sig.signature->dupctx(pctx->op.sig.algctx);

            if (rctx->op.sig.algctx == NULL) {
                UCI_SIGNATURE_free(rctx->op.sig.signature);
                rctx->op.sig.signature = NULL;
                goto err;
            }
            return rctx;
        }
    } else if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(pctx)) {
        if (pctx->op.ciph.cipher != NULL) {
            rctx->op.ciph.cipher = pctx->op.ciph.cipher;
            if (!UCI_ASYM_CIPHER_up_ref(rctx->op.ciph.cipher))
                goto err;
        }
        if (pctx->op.ciph.algctx != NULL) {
            if (!ossl_assert(pctx->op.ciph.cipher != NULL))
                goto err;

            if (pctx->op.ciph.cipher->dupctx != NULL)
                rctx->op.ciph.algctx
                    = pctx->op.ciph.cipher->dupctx(pctx->op.ciph.algctx);

            if (rctx->op.ciph.algctx == NULL) {
                UCI_ASYM_CIPHER_free(rctx->op.ciph.cipher);
                rctx->op.ciph.cipher = NULL;
                goto err;
            }
            return rctx;
        }
    } else if (UCI_PKEY_CTX_IS_KEM_OP(pctx)) {
        if (pctx->op.encap.kem != NULL) {
            rctx->op.encap.kem = pctx->op.encap.kem;
            if (!UCI_KEM_up_ref(rctx->op.encap.kem))
                goto err;
        }
        if (pctx->op.encap.algctx != NULL) {
            if (!ossl_assert(pctx->op.encap.kem != NULL))
                goto err;

            if (pctx->op.encap.kem->dupctx != NULL)
                rctx->op.encap.algctx
                    = pctx->op.encap.kem->dupctx(pctx->op.encap.algctx);

            if (rctx->op.encap.algctx == NULL) {
                UCI_KEM_free(rctx->op.encap.kem);
                rctx->op.encap.kem = NULL;
                goto err;
            }
            return rctx;
        }
    } else if (UCI_PKEY_CTX_IS_GEN_OP(pctx)) {
        /* Not supported - This would need a gen_dupctx() to work */
        goto err;
    }

    rctx->pmeth = pctx->pmeth;
# ifndef OPENSSL_NO_ENGINE
    rctx->engine = pctx->engine;
# endif

    if (pctx->peerkey != NULL && !UCI_PKEY_up_ref(pctx->peerkey))
        goto err;

    rctx->peerkey = pctx->peerkey;

    if (pctx->pmeth == NULL) {
        if (rctx->operation == UCI_PKEY_OP_UNDEFINED) {
            UCI_KEYMGMT *tmp_keymgmt = pctx->keymgmt;
            void *provkey;

            if (pctx->pkey == NULL)
                return rctx;

            provkey = uci_pkey_export_to_provider(pctx->pkey, pctx->libctx,
                                                  &tmp_keymgmt, pctx->propquery);
            if (provkey == NULL)
                goto err;
            if (!UCI_KEYMGMT_up_ref(tmp_keymgmt))
                goto err;
            UCI_KEYMGMT_free(rctx->keymgmt);
            rctx->keymgmt = tmp_keymgmt;
            return rctx;
        }
    } else if (pctx->pmeth->copy(rctx, pctx) > 0) {
        return rctx;
    }
err:
    rctx->pmeth = NULL;
    UCI_PKEY_CTX_free(rctx);
    return NULL;
}

int UCI_PKEY_meth_add0(const UCI_PKEY_METHOD *pmeth)
{
    if (app_pkey_methods == NULL) {
        app_pkey_methods = sk_UCI_PKEY_METHOD_new(pmeth_cmp);
        if (app_pkey_methods == NULL) {
            ERR_raise(ERR_LIB_EVP, ERR_R_CRYPTO_LIB);
            return 0;
        }
    }
    if (!sk_UCI_PKEY_METHOD_push(app_pkey_methods, pmeth)) {
        ERR_raise(ERR_LIB_EVP, ERR_R_CRYPTO_LIB);
        return 0;
    }
    sk_UCI_PKEY_METHOD_sort(app_pkey_methods);
    return 1;
}

void uci_app_cleanup_int(void)
{
    if (app_pkey_methods != NULL)
        sk_UCI_PKEY_METHOD_pop_free(app_pkey_methods, UCI_PKEY_meth_free);
}

int UCI_PKEY_meth_remove(const UCI_PKEY_METHOD *pmeth)
{
    const UCI_PKEY_METHOD *ret;

    ret = sk_UCI_PKEY_METHOD_delete_ptr(app_pkey_methods, pmeth);

    return ret == NULL ? 0 : 1;
}

size_t UCI_PKEY_meth_get_count(void)
{
    size_t rv = OSSL_NELEM(standard_methods);

    if (app_pkey_methods)
        rv += sk_UCI_PKEY_METHOD_num(app_pkey_methods);
    return rv;
}

const UCI_PKEY_METHOD *UCI_PKEY_meth_get0(size_t idx)
{
    if (idx < OSSL_NELEM(standard_methods))
        return (standard_methods[idx])();
    if (app_pkey_methods == NULL)
        return NULL;
    idx -= OSSL_NELEM(standard_methods);
    if (idx >= (size_t)sk_UCI_PKEY_METHOD_num(app_pkey_methods))
        return NULL;
    return sk_UCI_PKEY_METHOD_value(app_pkey_methods, (int)idx);
}
#endif

int UCI_PKEY_CTX_is_a(UCI_PKEY_CTX *ctx, const char *keytype)
{
#ifndef FIPS_MODULE
    if (uci_pkey_ctx_is_legacy(ctx))
        return (ctx->pmeth->pkey_id == uci_pkey_name2type(keytype));
#endif
    return UCI_KEYMGMT_is_a(ctx->keymgmt, keytype);
}

int UCI_PKEY_CTX_set_params(UCI_PKEY_CTX *ctx, const OSSL_PARAM *params)
{
    switch (uci_pkey_ctx_state(ctx)) {
    case UCI_PKEY_STATE_PROVIDER:
        if (UCI_PKEY_CTX_IS_DERIVE_OP(ctx)
            && ctx->op.kex.exchange != NULL
            && ctx->op.kex.exchange->set_ctx_params != NULL)
            return
                ctx->op.kex.exchange->set_ctx_params(ctx->op.kex.algctx,
                                                     params);
        if (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->set_ctx_params != NULL)
            return
                ctx->op.sig.signature->set_ctx_params(ctx->op.sig.algctx,
                                                      params);
        if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            && ctx->op.ciph.cipher != NULL
            && ctx->op.ciph.cipher->set_ctx_params != NULL)
            return
                ctx->op.ciph.cipher->set_ctx_params(ctx->op.ciph.algctx,
                                                    params);
        if (UCI_PKEY_CTX_IS_GEN_OP(ctx)
            && ctx->keymgmt != NULL
            && ctx->keymgmt->gen_set_params != NULL)
            return
                uci_keymgmt_gen_set_params(ctx->keymgmt, ctx->op.keymgmt.genctx,
                                           params);
        if (UCI_PKEY_CTX_IS_KEM_OP(ctx)
            && ctx->op.encap.kem != NULL
            && ctx->op.encap.kem->set_ctx_params != NULL)
            return
                ctx->op.encap.kem->set_ctx_params(ctx->op.encap.algctx,
                                                  params);
        break;
    case UCI_PKEY_STATE_UNKNOWN:
        break;
#ifndef FIPS_MODULE
    case UCI_PKEY_STATE_LEGACY:
        return uci_pkey_ctx_set_params_to_ctrl(ctx, params);
#endif
    }
    return 0;
}

int UCI_PKEY_CTX_get_params(UCI_PKEY_CTX *ctx, OSSL_PARAM *params)
{
    switch (uci_pkey_ctx_state(ctx)) {
    case UCI_PKEY_STATE_PROVIDER:
        if (UCI_PKEY_CTX_IS_DERIVE_OP(ctx)
            && ctx->op.kex.exchange != NULL
            && ctx->op.kex.exchange->get_ctx_params != NULL)
            return
                ctx->op.kex.exchange->get_ctx_params(ctx->op.kex.algctx,
                                                     params);
        if (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->get_ctx_params != NULL)
            return
                ctx->op.sig.signature->get_ctx_params(ctx->op.sig.algctx,
                                                      params);
        if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            && ctx->op.ciph.cipher != NULL
            && ctx->op.ciph.cipher->get_ctx_params != NULL)
            return
                ctx->op.ciph.cipher->get_ctx_params(ctx->op.ciph.algctx,
                                                    params);
        if (UCI_PKEY_CTX_IS_KEM_OP(ctx)
            && ctx->op.encap.kem != NULL
            && ctx->op.encap.kem->get_ctx_params != NULL)
            return
                ctx->op.encap.kem->get_ctx_params(ctx->op.encap.algctx,
                                                  params);
        if (UCI_PKEY_CTX_IS_GEN_OP(ctx)
            && ctx->keymgmt != NULL
            && ctx->keymgmt->gen_get_params != NULL)
            return
                uci_keymgmt_gen_get_params(ctx->keymgmt, ctx->op.keymgmt.genctx,
                                           params);
        break;
    case UCI_PKEY_STATE_UNKNOWN:
        break;
#ifndef FIPS_MODULE
    case UCI_PKEY_STATE_LEGACY:
        return uci_pkey_ctx_get_params_to_ctrl(ctx, params);
#endif
    }
    ERR_raise_data(ERR_LIB_EVP, UCI_R_PROVIDER_GET_CTX_PARAMS_NOT_SUPPORTED,
                   "UCI_PKEY_OP=0x%x", ctx->operation);
    return 0;
}

#ifndef FIPS_MODULE
const OSSL_PARAM *UCI_PKEY_CTX_gettable_params(const UCI_PKEY_CTX *ctx)
{
    void *provctx;

    if (UCI_PKEY_CTX_IS_DERIVE_OP(ctx)
            && ctx->op.kex.exchange != NULL
            && ctx->op.kex.exchange->gettable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(UCI_KEYEXCH_get0_provider(ctx->op.kex.exchange));
        return ctx->op.kex.exchange->gettable_ctx_params(ctx->op.kex.algctx,
                                                         provctx);
    }
    if (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->gettable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(
                      UCI_SIGNATURE_get0_provider(ctx->op.sig.signature));
        return ctx->op.sig.signature->gettable_ctx_params(ctx->op.sig.algctx,
                                                          provctx);
    }
    if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            && ctx->op.ciph.cipher != NULL
            && ctx->op.ciph.cipher->gettable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(
                      UCI_ASYM_CIPHER_get0_provider(ctx->op.ciph.cipher));
        return ctx->op.ciph.cipher->gettable_ctx_params(ctx->op.ciph.algctx,
                                                        provctx);
    }
    if (UCI_PKEY_CTX_IS_KEM_OP(ctx)
        && ctx->op.encap.kem != NULL
        && ctx->op.encap.kem->gettable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(UCI_KEM_get0_provider(ctx->op.encap.kem));
        return ctx->op.encap.kem->gettable_ctx_params(ctx->op.encap.algctx,
                                                      provctx);
    }
    if (UCI_PKEY_CTX_IS_GEN_OP(ctx)
            && ctx->keymgmt != NULL
            && ctx->keymgmt->gen_gettable_params != NULL) {
        provctx = ossl_provider_ctx(UCI_KEYMGMT_get0_provider(ctx->keymgmt));
        return ctx->keymgmt->gen_gettable_params(ctx->op.keymgmt.genctx,
                                                 provctx);
    }
    return NULL;
}

const OSSL_PARAM *UCI_PKEY_CTX_settable_params(const UCI_PKEY_CTX *ctx)
{
    void *provctx;

    if (UCI_PKEY_CTX_IS_DERIVE_OP(ctx)
            && ctx->op.kex.exchange != NULL
            && ctx->op.kex.exchange->settable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(UCI_KEYEXCH_get0_provider(ctx->op.kex.exchange));
        return ctx->op.kex.exchange->settable_ctx_params(ctx->op.kex.algctx,
                                                         provctx);
    }
    if (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)
            && ctx->op.sig.signature != NULL
            && ctx->op.sig.signature->settable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(
                      UCI_SIGNATURE_get0_provider(ctx->op.sig.signature));
        return ctx->op.sig.signature->settable_ctx_params(ctx->op.sig.algctx,
                                                          provctx);
    }
    if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            && ctx->op.ciph.cipher != NULL
            && ctx->op.ciph.cipher->settable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(
                      UCI_ASYM_CIPHER_get0_provider(ctx->op.ciph.cipher));
        return ctx->op.ciph.cipher->settable_ctx_params(ctx->op.ciph.algctx,
                                                        provctx);
    }
    if (UCI_PKEY_CTX_IS_GEN_OP(ctx)
            && ctx->keymgmt != NULL
            && ctx->keymgmt->gen_settable_params != NULL) {
        provctx = ossl_provider_ctx(UCI_KEYMGMT_get0_provider(ctx->keymgmt));
        return ctx->keymgmt->gen_settable_params(ctx->op.keymgmt.genctx,
                                                 provctx);
    }
    if (UCI_PKEY_CTX_IS_KEM_OP(ctx)
        && ctx->op.encap.kem != NULL
        && ctx->op.encap.kem->settable_ctx_params != NULL) {
        provctx = ossl_provider_ctx(UCI_KEM_get0_provider(ctx->op.encap.kem));
        return ctx->op.encap.kem->settable_ctx_params(ctx->op.encap.algctx,
                                                      provctx);
    }
    return NULL;
}

/*
 * Internal helpers for stricter UCI_PKEY_CTX_{set,get}_params().
 *
 * Return 1 on success, 0 or negative for errors.
 *
 * In particular they return -2 if any of the params is not supported.
 *
 * They are not available in FIPS_MODULE as they depend on
 *      - UCI_PKEY_CTX_{get,set}_params()
 *      - UCI_PKEY_CTX_{gettable,settable}_params()
 *
 */
int uci_pkey_ctx_set_params_strict(UCI_PKEY_CTX *ctx, OSSL_PARAM *params)
{
    if (ctx == NULL || params == NULL)
        return 0;

    /*
     * We only check for provider side UCI_PKEY_CTX.  For #legacy, we
     * depend on the translation that happens in UCI_PKEY_CTX_set_params()
     * call, and that the resulting ctrl call will return -2 if it doesn't
     * known the ctrl command number.
     */
    if (uci_pkey_ctx_is_provided(ctx)) {
        const OSSL_PARAM *settable = UCI_PKEY_CTX_settable_params(ctx);
        const OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++) {
            /* Check the ctx actually understands this parameter */
            if (OSSL_PARAM_locate_const(settable, p->key) == NULL)
                return -2;
        }
    }

    return UCI_PKEY_CTX_set_params(ctx, params);
}

int uci_pkey_ctx_get_params_strict(UCI_PKEY_CTX *ctx, OSSL_PARAM *params)
{
    if (ctx == NULL || params == NULL)
        return 0;

    /*
     * We only check for provider side UCI_PKEY_CTX.  For #legacy, we
     * depend on the translation that happens in UCI_PKEY_CTX_get_params()
     * call, and that the resulting ctrl call will return -2 if it doesn't
     * known the ctrl command number.
     */
    if (uci_pkey_ctx_is_provided(ctx)) {
        const OSSL_PARAM *gettable = UCI_PKEY_CTX_gettable_params(ctx);
        const OSSL_PARAM *p;

        for (p = params; p->key != NULL; p++) {
            /* Check the ctx actually understands this parameter */
            if (OSSL_PARAM_locate_const(gettable, p->key) == NULL)
                return -2;
        }
    }

    return UCI_PKEY_CTX_get_params(ctx, params);
}

int UCI_PKEY_CTX_get_signature_md(UCI_PKEY_CTX *ctx, const UCI_MD **md)
{
    OSSL_PARAM sig_md_params[2], *p = sig_md_params;
    /* 80 should be big enough */
    char name[80] = "";
    const UCI_MD *tmp;

    if (ctx == NULL || !UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as UCI_PKEY_CTX_ctrl */
        return -2;
    }

    if (ctx->op.sig.algctx == NULL)
        return UCI_PKEY_CTX_ctrl(ctx, -1, UCI_PKEY_OP_TYPE_SIG,
                                 UCI_PKEY_CTRL_GET_MD, 0, (void *)(md));

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                            name,
                                            sizeof(name));
    *p = OSSL_PARAM_construct_end();

    if (!UCI_PKEY_CTX_get_params(ctx, sig_md_params))
        return 0;

    tmp = uci_get_digestbyname_ex(ctx->libctx, name);
    if (tmp == NULL)
        return 0;

    *md = tmp;

    return 1;
}

static int uci_pkey_ctx_set_md(UCI_PKEY_CTX *ctx, const UCI_MD *md,
                               int fallback, const char *param, int op,
                               int ctrl)
{
    OSSL_PARAM md_params[2], *p = md_params;
    const char *name;

    if (ctx == NULL || (ctx->operation & op) == 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as UCI_PKEY_CTX_ctrl */
        return -2;
    }

    if (fallback)
        return UCI_PKEY_CTX_ctrl(ctx, -1, op, ctrl, 0, (void *)(md));

    if (md == NULL) {
        name = "";
    } else {
        name = UCI_MD_get0_name(md);
    }

    *p++ = OSSL_PARAM_construct_utf8_string(param,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)name, 0);
    *p = OSSL_PARAM_construct_end();

    return UCI_PKEY_CTX_set_params(ctx, md_params);
}

int UCI_PKEY_CTX_set_signature_md(UCI_PKEY_CTX *ctx, const UCI_MD *md)
{
    return uci_pkey_ctx_set_md(ctx, md, ctx->op.sig.algctx == NULL,
                               OSSL_SIGNATURE_PARAM_DIGEST,
                               UCI_PKEY_OP_TYPE_SIG, UCI_PKEY_CTRL_MD);
}

int UCI_PKEY_CTX_set_tls1_prf_md(UCI_PKEY_CTX *ctx, const UCI_MD *md)
{
    return uci_pkey_ctx_set_md(ctx, md, ctx->op.kex.algctx == NULL,
                               OSSL_KDF_PARAM_DIGEST,
                               UCI_PKEY_OP_DERIVE, UCI_PKEY_CTRL_TLS_MD);
}

static int uci_pkey_ctx_set1_octet_string(UCI_PKEY_CTX *ctx, int fallback,
                                          const char *param, int op, int ctrl,
                                          const unsigned char *data,
                                          int datalen)
{
    OSSL_PARAM octet_string_params[2], *p = octet_string_params;

    if (ctx == NULL || (ctx->operation & op) == 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as UCI_PKEY_CTX_ctrl */
        return -2;
    }

    /* Code below to be removed when legacy support is dropped. */
    if (fallback)
        return UCI_PKEY_CTX_ctrl(ctx, -1, op, ctrl, datalen, (void *)(data));
    /* end of legacy support */

    if (datalen < 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_LENGTH);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_octet_string(param,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (unsigned char *)data,
                                            (size_t)datalen);
    *p = OSSL_PARAM_construct_end();

    return UCI_PKEY_CTX_set_params(ctx, octet_string_params);
}

static int uci_pkey_ctx_add1_octet_string(UCI_PKEY_CTX *ctx, int fallback,
                                          const char *param, int op, int ctrl,
                                          const unsigned char *data,
                                          int datalen)
{
    OSSL_PARAM os_params[2];
    const OSSL_PARAM *gettables;
    unsigned char *info = NULL;
    size_t info_len = 0;
    size_t info_alloc = 0;
    int ret = 0;

    if (ctx == NULL || (ctx->operation & op) == 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as UCI_PKEY_CTX_ctrl */
        return -2;
    }

    /* Code below to be removed when legacy support is dropped. */
    if (fallback)
        return UCI_PKEY_CTX_ctrl(ctx, -1, op, ctrl, datalen, (void *)(data));
    /* end of legacy support */

    if (datalen < 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_LENGTH);
        return 0;
    } else if (datalen == 0) {
        return 1;
    }

    /* Check for older provider that doesn't support getting this parameter */
    gettables = UCI_PKEY_CTX_gettable_params(ctx);
    if (gettables == NULL || OSSL_PARAM_locate_const(gettables, param) == NULL)
        return uci_pkey_ctx_set1_octet_string(ctx, fallback, param, op, ctrl,
                                              data, datalen);

    /* Get the original value length */
    os_params[0] = OSSL_PARAM_construct_octet_string(param, NULL, 0);
    os_params[1] = OSSL_PARAM_construct_end();

    if (!UCI_PKEY_CTX_get_params(ctx, os_params))
        return 0;

    /* This should not happen but check to be sure. */
    if (os_params[0].return_size == OSSL_PARAM_UNMODIFIED)
        return 0;

    info_alloc = os_params[0].return_size + datalen;
    if (info_alloc == 0)
        return 0;
    info = OPENSSL_zalloc(info_alloc);
    if (info == NULL)
        return 0;
    info_len = os_params[0].return_size;

    os_params[0] = OSSL_PARAM_construct_octet_string(param, info, info_alloc);

    /* if we have data, then go get it */
    if (info_len > 0) {
        if (!UCI_PKEY_CTX_get_params(ctx, os_params))
            goto error;
    }

    /* Copy the input data */
    memcpy(&info[info_len], data, datalen);
    ret = UCI_PKEY_CTX_set_params(ctx, os_params);

 error:
    OPENSSL_clear_free(info, info_alloc);
    return ret;
}

int UCI_PKEY_CTX_set1_tls1_prf_secret(UCI_PKEY_CTX *ctx,
                                      const unsigned char *sec, int seclen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_SECRET,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_TLS_SECRET,
                                          sec, seclen);
}

int UCI_PKEY_CTX_add1_tls1_prf_seed(UCI_PKEY_CTX *ctx,
                                    const unsigned char *seed, int seedlen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_SEED,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_TLS_SEED,
                                          seed, seedlen);
}

int UCI_PKEY_CTX_set_hkdf_md(UCI_PKEY_CTX *ctx, const UCI_MD *md)
{
    return uci_pkey_ctx_set_md(ctx, md, ctx->op.kex.algctx == NULL,
                               OSSL_KDF_PARAM_DIGEST,
                               UCI_PKEY_OP_DERIVE, UCI_PKEY_CTRL_HKDF_MD);
}

int UCI_PKEY_CTX_set1_hkdf_salt(UCI_PKEY_CTX *ctx,
                                const unsigned char *salt, int saltlen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_SALT,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_HKDF_SALT,
                                          salt, saltlen);
}

int UCI_PKEY_CTX_set1_hkdf_key(UCI_PKEY_CTX *ctx,
                                      const unsigned char *key, int keylen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_KEY,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_HKDF_KEY,
                                          key, keylen);
}

int UCI_PKEY_CTX_add1_hkdf_info(UCI_PKEY_CTX *ctx,
                                      const unsigned char *info, int infolen)
{
    return uci_pkey_ctx_add1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_INFO,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_HKDF_INFO,
                                          info, infolen);
}

int UCI_PKEY_CTX_set_hkdf_mode(UCI_PKEY_CTX *ctx, int mode)
{
    OSSL_PARAM int_params[2], *p = int_params;

    if (ctx == NULL || !UCI_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as UCI_PKEY_CTX_ctrl */
        return -2;
    }

    /* Code below to be removed when legacy support is dropped. */
    if (ctx->op.kex.algctx == NULL)
        return UCI_PKEY_CTX_ctrl(ctx, -1, UCI_PKEY_OP_DERIVE,
                                 UCI_PKEY_CTRL_HKDF_MODE, mode, NULL);
    /* end of legacy support */

    if (mode < 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_VALUE);
        return 0;
    }

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p = OSSL_PARAM_construct_end();

    return UCI_PKEY_CTX_set_params(ctx, int_params);
}

int UCI_PKEY_CTX_set1_pbe_pass(UCI_PKEY_CTX *ctx, const char *pass,
                               int passlen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_PASSWORD,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_PASS,
                                          (const unsigned char *)pass, passlen);
}

int UCI_PKEY_CTX_set1_scrypt_salt(UCI_PKEY_CTX *ctx,
                                  const unsigned char *salt, int saltlen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.kex.algctx == NULL,
                                          OSSL_KDF_PARAM_SALT,
                                          UCI_PKEY_OP_DERIVE,
                                          UCI_PKEY_CTRL_SCRYPT_SALT,
                                          salt, saltlen);
}

static int uci_pkey_ctx_set_uint64(UCI_PKEY_CTX *ctx, const char *param,
                                   int op, int ctrl, uint64_t val)
{
    OSSL_PARAM uint64_params[2], *p = uint64_params;

    if (ctx == NULL || !UCI_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as UCI_PKEY_CTX_ctrl */
        return -2;
    }

    /* Code below to be removed when legacy support is dropped. */
    if (ctx->op.kex.algctx == NULL)
        return UCI_PKEY_CTX_ctrl_uint64(ctx, -1, op, ctrl, val);
    /* end of legacy support */

    *p++ = OSSL_PARAM_construct_uint64(param, &val);
    *p = OSSL_PARAM_construct_end();

    return UCI_PKEY_CTX_set_params(ctx, uint64_params);
}

int UCI_PKEY_CTX_set_scrypt_N(UCI_PKEY_CTX *ctx, uint64_t n)
{
    return uci_pkey_ctx_set_uint64(ctx, OSSL_KDF_PARAM_SCRYPT_N,
                                   UCI_PKEY_OP_DERIVE, UCI_PKEY_CTRL_SCRYPT_N,
                                   n);
}

int UCI_PKEY_CTX_set_scrypt_r(UCI_PKEY_CTX *ctx, uint64_t r)
{
    return uci_pkey_ctx_set_uint64(ctx, OSSL_KDF_PARAM_SCRYPT_R,
                                   UCI_PKEY_OP_DERIVE, UCI_PKEY_CTRL_SCRYPT_R,
                                   r);
}

int UCI_PKEY_CTX_set_scrypt_p(UCI_PKEY_CTX *ctx, uint64_t p)
{
    return uci_pkey_ctx_set_uint64(ctx, OSSL_KDF_PARAM_SCRYPT_P,
                                   UCI_PKEY_OP_DERIVE, UCI_PKEY_CTRL_SCRYPT_P,
                                   p);
}

int UCI_PKEY_CTX_set_scrypt_maxmem_bytes(UCI_PKEY_CTX *ctx,
                                         uint64_t maxmem_bytes)
{
    return uci_pkey_ctx_set_uint64(ctx, OSSL_KDF_PARAM_SCRYPT_MAXMEM,
                                   UCI_PKEY_OP_DERIVE,
                                   UCI_PKEY_CTRL_SCRYPT_MAXMEM_BYTES,
                                   maxmem_bytes);
}

int UCI_PKEY_CTX_set_mac_key(UCI_PKEY_CTX *ctx, const unsigned char *key,
                             int keylen)
{
    return uci_pkey_ctx_set1_octet_string(ctx, ctx->op.keymgmt.genctx == NULL,
                                          OSSL_PKEY_PARAM_PRIV_KEY,
                                          UCI_PKEY_OP_KEYGEN,
                                          UCI_PKEY_CTRL_SET_MAC_KEY,
                                          key, keylen);
}

int UCI_PKEY_CTX_set_kem_op(UCI_PKEY_CTX *ctx, const char *op)
{
    OSSL_PARAM params[2], *p = params;

    if (ctx == NULL || op == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_VALUE);
        return 0;
    }
    if (!UCI_PKEY_CTX_IS_KEM_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                            (char *)op, 0);
    *p = OSSL_PARAM_construct_end();
    return UCI_PKEY_CTX_set_params(ctx, params);
}

int UCI_PKEY_CTX_set1_id(UCI_PKEY_CTX *ctx, const void *id, int len)
{
    return UCI_PKEY_CTX_ctrl(ctx, -1, -1,
                             UCI_PKEY_CTRL_SET1_ID, (int)len, (void*)(id));
}

int UCI_PKEY_CTX_get1_id(UCI_PKEY_CTX *ctx, void *id)
{
    return UCI_PKEY_CTX_ctrl(ctx, -1, -1, UCI_PKEY_CTRL_GET1_ID, 0, (void*)id);
}

int UCI_PKEY_CTX_get1_id_len(UCI_PKEY_CTX *ctx, size_t *id_len)
{
    return UCI_PKEY_CTX_ctrl(ctx, -1, -1,
                             UCI_PKEY_CTRL_GET1_ID_LEN, 0, (void*)id_len);
}

static int uci_pkey_ctx_ctrl_int(UCI_PKEY_CTX *ctx, int keytype, int optype,
                                 int cmd, int p1, void *p2)
{
    int ret = 0;

    /*
     * If the method has a |digest_custom| function, we can relax the
     * operation type check, since this can be called before the operation
     * is initialized.
     */
    if (ctx->pmeth == NULL || ctx->pmeth->digest_custom == NULL) {
        if (ctx->operation == UCI_PKEY_OP_UNDEFINED) {
            ERR_raise(ERR_LIB_EVP, UCI_R_NO_OPERATION_SET);
            return -1;
        }

        if ((optype != -1) && !(ctx->operation & optype)) {
            ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_OPERATION);
            return -1;
        }
    }

    switch (uci_pkey_ctx_state(ctx)) {
    case UCI_PKEY_STATE_PROVIDER:
        return uci_pkey_ctx_ctrl_to_param(ctx, keytype, optype, cmd, p1, p2);
    case UCI_PKEY_STATE_UNKNOWN:
    case UCI_PKEY_STATE_LEGACY:
        if (ctx->pmeth == NULL || ctx->pmeth->ctrl == NULL) {
            ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
            return -2;
        }
        if ((keytype != -1) && (ctx->pmeth->pkey_id != keytype))
            return -1;

        ret = ctx->pmeth->ctrl(ctx, cmd, p1, p2);

        if (ret == -2)
            ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        break;
    }
    return ret;
}

int UCI_PKEY_CTX_ctrl(UCI_PKEY_CTX *ctx, int keytype, int optype,
                      int cmd, int p1, void *p2)
{
    int ret = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }
    /* If unsupported, we don't want that reported here */
    ERR_set_mark();
    ret = uci_pkey_ctx_store_cached_data(ctx, keytype, optype,
                                         cmd, NULL, p2, p1);
    if (ret == -2) {
        ERR_pop_to_mark();
    } else {
        ERR_clear_last_mark();
        /*
         * If there was an error, there was an error.
         * If the operation isn't initialized yet, we also return, as
         * the saved values will be used then anyway.
         */
        if (ret < 1 || ctx->operation == UCI_PKEY_OP_UNDEFINED)
            return ret;
    }
    return uci_pkey_ctx_ctrl_int(ctx, keytype, optype, cmd, p1, p2);
}

int UCI_PKEY_CTX_ctrl_uint64(UCI_PKEY_CTX *ctx, int keytype, int optype,
                             int cmd, uint64_t value)
{
    return UCI_PKEY_CTX_ctrl(ctx, keytype, optype, cmd, 0, &value);
}


static int uci_pkey_ctx_ctrl_str_int(UCI_PKEY_CTX *ctx,
                                     const char *name, const char *value)
{
    int ret = 0;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    switch (uci_pkey_ctx_state(ctx)) {
    case UCI_PKEY_STATE_PROVIDER:
        return uci_pkey_ctx_ctrl_str_to_param(ctx, name, value);
    case UCI_PKEY_STATE_UNKNOWN:
    case UCI_PKEY_STATE_LEGACY:
        if (ctx == NULL || ctx->pmeth == NULL || ctx->pmeth->ctrl_str == NULL) {
            ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
            return -2;
        }
        if (strcmp(name, "digest") == 0)
            ret = UCI_PKEY_CTX_md(ctx,
                                  UCI_PKEY_OP_TYPE_SIG | UCI_PKEY_OP_TYPE_CRYPT,
                                  UCI_PKEY_CTRL_MD, value);
        else
            ret = ctx->pmeth->ctrl_str(ctx, name, value);
        break;
    }

    return ret;
}

int UCI_PKEY_CTX_ctrl_str(UCI_PKEY_CTX *ctx,
                          const char *name, const char *value)
{
    int ret = 0;

    /* If unsupported, we don't want that reported here */
    ERR_set_mark();
    ret = uci_pkey_ctx_store_cached_data(ctx, -1, -1, -1,
                                         name, value, strlen(value) + 1);
    if (ret == -2) {
        ERR_pop_to_mark();
    } else {
        ERR_clear_last_mark();
        /*
         * If there was an error, there was an error.
         * If the operation isn't initialized yet, we also return, as
         * the saved values will be used then anyway.
         */
        if (ret < 1 || ctx->operation == UCI_PKEY_OP_UNDEFINED)
            return ret;
    }

    return uci_pkey_ctx_ctrl_str_int(ctx, name, value);
}

static int decode_cmd(int cmd, const char *name)
{
    if (cmd == -1) {
        /*
         * The consequence of the assertion not being true is that this
         * function will return -1, which will cause the calling functions
         * to signal that the command is unsupported...  in non-debug mode.
         */
        if (ossl_assert(name != NULL))
            if (strcmp(name, "distid") == 0 || strcmp(name, "hexdistid") == 0)
                cmd = UCI_PKEY_CTRL_SET1_ID;
    }

    return cmd;
}

static int uci_pkey_ctx_store_cached_data(UCI_PKEY_CTX *ctx,
                                          int keytype, int optype,
                                          int cmd, const char *name,
                                          const void *data, size_t data_len)
{
    /*
     * Check that it's one of the supported commands.  The ctrl commands
     * number cases here must correspond to the cases in the bottom switch
     * in this function.
     */
    switch (cmd = decode_cmd(cmd, name)) {
    case UCI_PKEY_CTRL_SET1_ID:
        break;
    default:
        ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    if (keytype != -1) {
        switch (uci_pkey_ctx_state(ctx)) {
        case UCI_PKEY_STATE_PROVIDER:
            if (ctx->keymgmt == NULL) {
                ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
                return -2;
            }
            if (!UCI_KEYMGMT_is_a(ctx->keymgmt,
                                  uci_pkey_type2name(keytype))) {
                ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_OPERATION);
                return -1;
            }
            break;
        case UCI_PKEY_STATE_UNKNOWN:
        case UCI_PKEY_STATE_LEGACY:
            if (ctx->pmeth == NULL) {
                ERR_raise(ERR_LIB_EVP, UCI_R_COMMAND_NOT_SUPPORTED);
                return -2;
            }
            if (UCI_PKEY_type(ctx->pmeth->pkey_id) != UCI_PKEY_type(keytype)) {
                ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_OPERATION);
                return -1;
            }
            break;
        }
    }
    if (optype != -1 && (ctx->operation & optype) == 0) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_OPERATION);
        return -1;
    }

    switch (cmd) {
    case UCI_PKEY_CTRL_SET1_ID:
        uci_pkey_ctx_free_cached_data(ctx, cmd, name);
        if (name != NULL) {
            ctx->cached_parameters.dist_id_name = OPENSSL_strdup(name);
            if (ctx->cached_parameters.dist_id_name == NULL)
                return 0;
        }
        if (data_len > 0) {
            ctx->cached_parameters.dist_id = OPENSSL_memdup(data, data_len);
            if (ctx->cached_parameters.dist_id == NULL)
                return 0;
        }
        ctx->cached_parameters.dist_id_set = 1;
        ctx->cached_parameters.dist_id_len = data_len;
        break;
    }
    return 1;
}

static void uci_pkey_ctx_free_cached_data(UCI_PKEY_CTX *ctx,
                                          int cmd, const char *name)
{
    cmd = decode_cmd(cmd, name);
    switch (cmd) {
    case UCI_PKEY_CTRL_SET1_ID:
        OPENSSL_free(ctx->cached_parameters.dist_id);
        OPENSSL_free(ctx->cached_parameters.dist_id_name);
        ctx->cached_parameters.dist_id = NULL;
        ctx->cached_parameters.dist_id_name = NULL;
        break;
    }
}

static void uci_pkey_ctx_free_all_cached_data(UCI_PKEY_CTX *ctx)
{
    uci_pkey_ctx_free_cached_data(ctx, UCI_PKEY_CTRL_SET1_ID, NULL);
}

int uci_pkey_ctx_use_cached_data(UCI_PKEY_CTX *ctx)
{
    int ret = 1;

    if (ret && ctx->cached_parameters.dist_id_set) {
        const char *name = ctx->cached_parameters.dist_id_name;
        const void *val = ctx->cached_parameters.dist_id;
        size_t len = ctx->cached_parameters.dist_id_len;

        if (name != NULL)
            ret = uci_pkey_ctx_ctrl_str_int(ctx, name, val);
        else
            ret = uci_pkey_ctx_ctrl_int(ctx, -1, ctx->operation,
                                        UCI_PKEY_CTRL_SET1_ID,
                                        (int)len, (void *)val);
    }

    return ret;
}

OSSL_LIB_CTX *UCI_PKEY_CTX_get0_libctx(UCI_PKEY_CTX *ctx)
{
    return ctx->libctx;
}

const char *UCI_PKEY_CTX_get0_propq(const UCI_PKEY_CTX *ctx)
{
    return ctx->propquery;
}

const OSSL_PROVIDER *UCI_PKEY_CTX_get0_provider(const UCI_PKEY_CTX *ctx)
{
    if (UCI_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        if (ctx->op.sig.signature != NULL)
            return UCI_SIGNATURE_get0_provider(ctx->op.sig.signature);
    } else if (UCI_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        if (ctx->op.kex.exchange != NULL)
            return UCI_KEYEXCH_get0_provider(ctx->op.kex.exchange);
    } else if (UCI_PKEY_CTX_IS_KEM_OP(ctx)) {
        if (ctx->op.encap.kem != NULL)
            return UCI_KEM_get0_provider(ctx->op.encap.kem);
    } else if (UCI_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        if (ctx->op.ciph.cipher != NULL)
            return UCI_ASYM_CIPHER_get0_provider(ctx->op.ciph.cipher);
    } else if (UCI_PKEY_CTX_IS_GEN_OP(ctx)) {
        if (ctx->keymgmt != NULL)
            return UCI_KEYMGMT_get0_provider(ctx->keymgmt);
    }

    return NULL;
}

/* Utility functions to send a string of hex string to a ctrl */

int UCI_PKEY_CTX_str2ctrl(UCI_PKEY_CTX *ctx, int cmd, const char *str)
{
    size_t len;

    len = strlen(str);
    if (len > INT_MAX)
        return -1;
    return ctx->pmeth->ctrl(ctx, cmd, (int)len, (void *)str);
}

int UCI_PKEY_CTX_hex2ctrl(UCI_PKEY_CTX *ctx, int cmd, const char *hex)
{
    unsigned char *bin;
    long binlen;
    int rv = -1;

    bin = OPENSSL_hexstr2buf(hex, &binlen);
    if (bin == NULL)
        return 0;
    if (binlen <= INT_MAX)
        rv = ctx->pmeth->ctrl(ctx, cmd, binlen, bin);
    OPENSSL_free(bin);
    return rv;
}

/* Pass a message digest to a ctrl */
int UCI_PKEY_CTX_md(UCI_PKEY_CTX *ctx, int optype, int cmd, const char *md)
{
    const UCI_MD *m;

    if (md == NULL || (m = UCI_get_digestbyname(md)) == NULL) {
        ERR_raise(ERR_LIB_EVP, UCI_R_INVALID_DIGEST);
        return 0;
    }
    return UCI_PKEY_CTX_ctrl(ctx, -1, optype, cmd, 0, (void *)m);
}

int UCI_PKEY_CTX_get_operation(UCI_PKEY_CTX *ctx)
{
    return ctx->operation;
}

void UCI_PKEY_CTX_set0_keygen_info(UCI_PKEY_CTX *ctx, int *dat, int datlen)
{
    ctx->keygen_info = dat;
    ctx->keygen_info_count = datlen;
}

void UCI_PKEY_CTX_set_data(UCI_PKEY_CTX *ctx, void *data)
{
    ctx->data = data;
}

void *UCI_PKEY_CTX_get_data(const UCI_PKEY_CTX *ctx)
{
    return ctx->data;
}

UCI_PKEY *UCI_PKEY_CTX_get0_pkey(UCI_PKEY_CTX *ctx)
{
    return ctx->pkey;
}

UCI_PKEY *UCI_PKEY_CTX_get0_peerkey(UCI_PKEY_CTX *ctx)
{
    return ctx->peerkey;
}

void UCI_PKEY_CTX_set_app_data(UCI_PKEY_CTX *ctx, void *data)
{
    ctx->app_data = data;
}

void *UCI_PKEY_CTX_get_app_data(UCI_PKEY_CTX *ctx)
{
    return ctx->app_data;
}

void UCI_PKEY_meth_set_init(UCI_PKEY_METHOD *pmeth,
                            int (*init) (UCI_PKEY_CTX *ctx))
{
    pmeth->init = init;
}

void UCI_PKEY_meth_set_copy(UCI_PKEY_METHOD *pmeth,
                            int (*copy) (UCI_PKEY_CTX *dst,
                                         const UCI_PKEY_CTX *src))
{
    pmeth->copy = copy;
}

void UCI_PKEY_meth_set_cleanup(UCI_PKEY_METHOD *pmeth,
                               void (*cleanup) (UCI_PKEY_CTX *ctx))
{
    pmeth->cleanup = cleanup;
}

void UCI_PKEY_meth_set_paramgen(UCI_PKEY_METHOD *pmeth,
                                int (*paramgen_init) (UCI_PKEY_CTX *ctx),
                                int (*paramgen) (UCI_PKEY_CTX *ctx,
                                                 UCI_PKEY *pkey))
{
    pmeth->paramgen_init = paramgen_init;
    pmeth->paramgen = paramgen;
}

void UCI_PKEY_meth_set_keygen(UCI_PKEY_METHOD *pmeth,
                              int (*keygen_init) (UCI_PKEY_CTX *ctx),
                              int (*keygen) (UCI_PKEY_CTX *ctx,
                                             UCI_PKEY *pkey))
{
    pmeth->keygen_init = keygen_init;
    pmeth->keygen = keygen;
}

void UCI_PKEY_meth_set_sign(UCI_PKEY_METHOD *pmeth,
                            int (*sign_init) (UCI_PKEY_CTX *ctx),
                            int (*sign) (UCI_PKEY_CTX *ctx,
                                         unsigned char *sig, size_t *siglen,
                                         const unsigned char *tbs,
                                         size_t tbslen))
{
    pmeth->sign_init = sign_init;
    pmeth->sign = sign;
}

void UCI_PKEY_meth_set_verify(UCI_PKEY_METHOD *pmeth,
                              int (*verify_init) (UCI_PKEY_CTX *ctx),
                              int (*verify) (UCI_PKEY_CTX *ctx,
                                             const unsigned char *sig,
                                             size_t siglen,
                                             const unsigned char *tbs,
                                             size_t tbslen))
{
    pmeth->verify_init = verify_init;
    pmeth->verify = verify;
}

void UCI_PKEY_meth_set_verify_recover(UCI_PKEY_METHOD *pmeth,
                                      int (*verify_recover_init) (UCI_PKEY_CTX
                                                                  *ctx),
                                      int (*verify_recover) (UCI_PKEY_CTX
                                                             *ctx,
                                                             unsigned char
                                                             *sig,
                                                             size_t *siglen,
                                                             const unsigned
                                                             char *tbs,
                                                             size_t tbslen))
{
    pmeth->verify_recover_init = verify_recover_init;
    pmeth->verify_recover = verify_recover;
}

void UCI_PKEY_meth_set_signctx(UCI_PKEY_METHOD *pmeth,
                               int (*signctx_init) (UCI_PKEY_CTX *ctx,
                                                    UCI_MD_CTX *mctx),
                               int (*signctx) (UCI_PKEY_CTX *ctx,
                                               unsigned char *sig,
                                               size_t *siglen,
                                               UCI_MD_CTX *mctx))
{
    pmeth->signctx_init = signctx_init;
    pmeth->signctx = signctx;
}

void UCI_PKEY_meth_set_verifyctx(UCI_PKEY_METHOD *pmeth,
                                 int (*verifyctx_init) (UCI_PKEY_CTX *ctx,
                                                        UCI_MD_CTX *mctx),
                                 int (*verifyctx) (UCI_PKEY_CTX *ctx,
                                                   const unsigned char *sig,
                                                   int siglen,
                                                   UCI_MD_CTX *mctx))
{
    pmeth->verifyctx_init = verifyctx_init;
    pmeth->verifyctx = verifyctx;
}

void UCI_PKEY_meth_set_encrypt(UCI_PKEY_METHOD *pmeth,
                               int (*encrypt_init) (UCI_PKEY_CTX *ctx),
                               int (*encryptfn) (UCI_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    pmeth->encrypt_init = encrypt_init;
    pmeth->encrypt = encryptfn;
}

void UCI_PKEY_meth_set_decrypt(UCI_PKEY_METHOD *pmeth,
                               int (*decrypt_init) (UCI_PKEY_CTX *ctx),
                               int (*decrypt) (UCI_PKEY_CTX *ctx,
                                               unsigned char *out,
                                               size_t *outlen,
                                               const unsigned char *in,
                                               size_t inlen))
{
    pmeth->decrypt_init = decrypt_init;
    pmeth->decrypt = decrypt;
}

void UCI_PKEY_meth_set_derive(UCI_PKEY_METHOD *pmeth,
                              int (*derive_init) (UCI_PKEY_CTX *ctx),
                              int (*derive) (UCI_PKEY_CTX *ctx,
                                             unsigned char *key,
                                             size_t *keylen))
{
    pmeth->derive_init = derive_init;
    pmeth->derive = derive;
}

void UCI_PKEY_meth_set_ctrl(UCI_PKEY_METHOD *pmeth,
                            int (*ctrl) (UCI_PKEY_CTX *ctx, int type, int p1,
                                         void *p2),
                            int (*ctrl_str) (UCI_PKEY_CTX *ctx,
                                             const char *type,
                                             const char *value))
{
    pmeth->ctrl = ctrl;
    pmeth->ctrl_str = ctrl_str;
}

void UCI_PKEY_meth_set_digestsign(UCI_PKEY_METHOD *pmeth,
    int (*digestsign) (UCI_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen))
{
    pmeth->digestsign = digestsign;
}

void UCI_PKEY_meth_set_digestverify(UCI_PKEY_METHOD *pmeth,
    int (*digestverify) (UCI_MD_CTX *ctx, const unsigned char *sig,
                         size_t siglen, const unsigned char *tbs,
                         size_t tbslen))
{
    pmeth->digestverify = digestverify;
}

void UCI_PKEY_meth_set_check(UCI_PKEY_METHOD *pmeth,
                             int (*check) (UCI_PKEY *pkey))
{
    pmeth->check = check;
}

void UCI_PKEY_meth_set_public_check(UCI_PKEY_METHOD *pmeth,
                                    int (*check) (UCI_PKEY *pkey))
{
    pmeth->public_check = check;
}

void UCI_PKEY_meth_set_param_check(UCI_PKEY_METHOD *pmeth,
                                   int (*check) (UCI_PKEY *pkey))
{
    pmeth->param_check = check;
}

void UCI_PKEY_meth_set_digest_custom(UCI_PKEY_METHOD *pmeth,
                                     int (*digest_custom) (UCI_PKEY_CTX *ctx,
                                                           UCI_MD_CTX *mctx))
{
    pmeth->digest_custom = digest_custom;
}

void UCI_PKEY_meth_get_init(const UCI_PKEY_METHOD *pmeth,
                            int (**pinit) (UCI_PKEY_CTX *ctx))
{
    *pinit = pmeth->init;
}

void UCI_PKEY_meth_get_copy(const UCI_PKEY_METHOD *pmeth,
                            int (**pcopy) (UCI_PKEY_CTX *dst,
                                           const UCI_PKEY_CTX *src))
{
    *pcopy = pmeth->copy;
}

void UCI_PKEY_meth_get_cleanup(const UCI_PKEY_METHOD *pmeth,
                               void (**pcleanup) (UCI_PKEY_CTX *ctx))
{
    *pcleanup = pmeth->cleanup;
}

void UCI_PKEY_meth_get_paramgen(const UCI_PKEY_METHOD *pmeth,
                                int (**pparamgen_init) (UCI_PKEY_CTX *ctx),
                                int (**pparamgen) (UCI_PKEY_CTX *ctx,
                                                   UCI_PKEY *pkey))
{
    if (pparamgen_init)
        *pparamgen_init = pmeth->paramgen_init;
    if (pparamgen)
        *pparamgen = pmeth->paramgen;
}

void UCI_PKEY_meth_get_keygen(const UCI_PKEY_METHOD *pmeth,
                              int (**pkeygen_init) (UCI_PKEY_CTX *ctx),
                              int (**pkeygen) (UCI_PKEY_CTX *ctx,
                                               UCI_PKEY *pkey))
{
    if (pkeygen_init)
        *pkeygen_init = pmeth->keygen_init;
    if (pkeygen)
        *pkeygen = pmeth->keygen;
}

void UCI_PKEY_meth_get_sign(const UCI_PKEY_METHOD *pmeth,
                            int (**psign_init) (UCI_PKEY_CTX *ctx),
                            int (**psign) (UCI_PKEY_CTX *ctx,
                                           unsigned char *sig, size_t *siglen,
                                           const unsigned char *tbs,
                                           size_t tbslen))
{
    if (psign_init)
        *psign_init = pmeth->sign_init;
    if (psign)
        *psign = pmeth->sign;
}

void UCI_PKEY_meth_get_verify(const UCI_PKEY_METHOD *pmeth,
                              int (**pverify_init) (UCI_PKEY_CTX *ctx),
                              int (**pverify) (UCI_PKEY_CTX *ctx,
                                               const unsigned char *sig,
                                               size_t siglen,
                                               const unsigned char *tbs,
                                               size_t tbslen))
{
    if (pverify_init)
        *pverify_init = pmeth->verify_init;
    if (pverify)
        *pverify = pmeth->verify;
}

void UCI_PKEY_meth_get_verify_recover(const UCI_PKEY_METHOD *pmeth,
                                      int (**pverify_recover_init) (UCI_PKEY_CTX
                                                                    *ctx),
                                      int (**pverify_recover) (UCI_PKEY_CTX
                                                               *ctx,
                                                               unsigned char
                                                               *sig,
                                                               size_t *siglen,
                                                               const unsigned
                                                               char *tbs,
                                                               size_t tbslen))
{
    if (pverify_recover_init)
        *pverify_recover_init = pmeth->verify_recover_init;
    if (pverify_recover)
        *pverify_recover = pmeth->verify_recover;
}

void UCI_PKEY_meth_get_signctx(const UCI_PKEY_METHOD *pmeth,
                               int (**psignctx_init) (UCI_PKEY_CTX *ctx,
                                                      UCI_MD_CTX *mctx),
                               int (**psignctx) (UCI_PKEY_CTX *ctx,
                                                 unsigned char *sig,
                                                 size_t *siglen,
                                                 UCI_MD_CTX *mctx))
{
    if (psignctx_init)
        *psignctx_init = pmeth->signctx_init;
    if (psignctx)
        *psignctx = pmeth->signctx;
}

void UCI_PKEY_meth_get_verifyctx(const UCI_PKEY_METHOD *pmeth,
                                 int (**pverifyctx_init) (UCI_PKEY_CTX *ctx,
                                                          UCI_MD_CTX *mctx),
                                 int (**pverifyctx) (UCI_PKEY_CTX *ctx,
                                                     const unsigned char *sig,
                                                     int siglen,
                                                     UCI_MD_CTX *mctx))
{
    if (pverifyctx_init)
        *pverifyctx_init = pmeth->verifyctx_init;
    if (pverifyctx)
        *pverifyctx = pmeth->verifyctx;
}

void UCI_PKEY_meth_get_encrypt(const UCI_PKEY_METHOD *pmeth,
                               int (**pencrypt_init) (UCI_PKEY_CTX *ctx),
                               int (**pencryptfn) (UCI_PKEY_CTX *ctx,
                                                   unsigned char *out,
                                                   size_t *outlen,
                                                   const unsigned char *in,
                                                   size_t inlen))
{
    if (pencrypt_init)
        *pencrypt_init = pmeth->encrypt_init;
    if (pencryptfn)
        *pencryptfn = pmeth->encrypt;
}

void UCI_PKEY_meth_get_decrypt(const UCI_PKEY_METHOD *pmeth,
                               int (**pdecrypt_init) (UCI_PKEY_CTX *ctx),
                               int (**pdecrypt) (UCI_PKEY_CTX *ctx,
                                                 unsigned char *out,
                                                 size_t *outlen,
                                                 const unsigned char *in,
                                                 size_t inlen))
{
    if (pdecrypt_init)
        *pdecrypt_init = pmeth->decrypt_init;
    if (pdecrypt)
        *pdecrypt = pmeth->decrypt;
}

void UCI_PKEY_meth_get_derive(const UCI_PKEY_METHOD *pmeth,
                              int (**pderive_init) (UCI_PKEY_CTX *ctx),
                              int (**pderive) (UCI_PKEY_CTX *ctx,
                                               unsigned char *key,
                                               size_t *keylen))
{
    if (pderive_init)
        *pderive_init = pmeth->derive_init;
    if (pderive)
        *pderive = pmeth->derive;
}

void UCI_PKEY_meth_get_ctrl(const UCI_PKEY_METHOD *pmeth,
                            int (**pctrl) (UCI_PKEY_CTX *ctx, int type, int p1,
                                           void *p2),
                            int (**pctrl_str) (UCI_PKEY_CTX *ctx,
                                               const char *type,
                                               const char *value))
{
    if (pctrl)
        *pctrl = pmeth->ctrl;
    if (pctrl_str)
        *pctrl_str = pmeth->ctrl_str;
}

void UCI_PKEY_meth_get_digestsign(const UCI_PKEY_METHOD *pmeth,
    int (**digestsign) (UCI_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen))
{
    if (digestsign)
        *digestsign = pmeth->digestsign;
}

void UCI_PKEY_meth_get_digestverify(const UCI_PKEY_METHOD *pmeth,
    int (**digestverify) (UCI_MD_CTX *ctx, const unsigned char *sig,
                          size_t siglen, const unsigned char *tbs,
                          size_t tbslen))
{
    if (digestverify)
        *digestverify = pmeth->digestverify;
}

void UCI_PKEY_meth_get_check(const UCI_PKEY_METHOD *pmeth,
                             int (**pcheck) (UCI_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->check;
}

void UCI_PKEY_meth_get_public_check(const UCI_PKEY_METHOD *pmeth,
                                    int (**pcheck) (UCI_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->public_check;
}

void UCI_PKEY_meth_get_param_check(const UCI_PKEY_METHOD *pmeth,
                                   int (**pcheck) (UCI_PKEY *pkey))
{
    if (pcheck != NULL)
        *pcheck = pmeth->param_check;
}

void UCI_PKEY_meth_get_digest_custom(const UCI_PKEY_METHOD *pmeth,
                                     int (**pdigest_custom) (UCI_PKEY_CTX *ctx,
                                                             UCI_MD_CTX *mctx))
{
    if (pdigest_custom != NULL)
        *pdigest_custom = pmeth->digest_custom;
}

#endif /* FIPS_MODULE */
