/*
 * Copyright 2015-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * EVP _meth_ APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>

#include <openssl/evp.h>
#include "crypto/evp.h"
#include "internal/provider.h"
#include "uci_local.h"

UCI_CIPHER *UCI_CIPHER_meth_new(int cipher_type, int block_size, int key_len)
{
    UCI_CIPHER *cipher = uci_cipher_new();

    if (cipher != NULL) {
        cipher->nid = cipher_type;
        cipher->block_size = block_size;
        cipher->key_len = key_len;
        cipher->origin = UCI_ORIG_METH;
    }
    return cipher;
}

UCI_CIPHER *UCI_CIPHER_meth_dup(const UCI_CIPHER *cipher)
{
    UCI_CIPHER *to = NULL;

    /*
     * Non-legacy UCI_CIPHERs can't be duplicated like this.
     * Use UCI_CIPHER_up_ref() instead.
     */
    if (cipher->prov != NULL)
        return NULL;

    if ((to = UCI_CIPHER_meth_new(cipher->nid, cipher->block_size,
                                  cipher->key_len)) != NULL) {
        CRYPTO_REF_COUNT refcnt = to->refcnt;

        memcpy(to, cipher, sizeof(*to));
        to->refcnt = refcnt;
        to->origin = UCI_ORIG_METH;
    }
    return to;
}

void UCI_CIPHER_meth_free(UCI_CIPHER *cipher)
{
    if (cipher == NULL || cipher->origin != UCI_ORIG_METH)
       return;

    uci_cipher_free_int(cipher);
}

int UCI_CIPHER_meth_set_iv_length(UCI_CIPHER *cipher, int iv_len)
{
    if (cipher->iv_len != 0)
        return 0;

    cipher->iv_len = iv_len;
    return 1;
}

int UCI_CIPHER_meth_set_flags(UCI_CIPHER *cipher, unsigned long flags)
{
    if (cipher->flags != 0)
        return 0;

    cipher->flags = flags;
    return 1;
}

int UCI_CIPHER_meth_set_impl_ctx_size(UCI_CIPHER *cipher, int ctx_size)
{
    if (cipher->ctx_size != 0)
        return 0;

    cipher->ctx_size = ctx_size;
    return 1;
}

int UCI_CIPHER_meth_set_init(UCI_CIPHER *cipher,
                             int (*init) (UCI_CIPHER_CTX *ctx,
                                          const unsigned char *key,
                                          const unsigned char *iv,
                                          int enc))
{
    if (cipher->init != NULL)
        return 0;

    cipher->init = init;
    return 1;
}

int UCI_CIPHER_meth_set_do_cipher(UCI_CIPHER *cipher,
                                  int (*do_cipher) (UCI_CIPHER_CTX *ctx,
                                                    unsigned char *out,
                                                    const unsigned char *in,
                                                    size_t inl))
{
    if (cipher->do_cipher != NULL)
        return 0;

    cipher->do_cipher = do_cipher;
    return 1;
}

int UCI_CIPHER_meth_set_cleanup(UCI_CIPHER *cipher,
                                int (*cleanup) (UCI_CIPHER_CTX *))
{
    if (cipher->cleanup != NULL)
        return 0;

    cipher->cleanup = cleanup;
    return 1;
}

int UCI_CIPHER_meth_set_set_asn1_params(UCI_CIPHER *cipher,
                                        int (*set_asn1_parameters) (UCI_CIPHER_CTX *,
                                                                    ASN1_TYPE *))
{
    if (cipher->set_asn1_parameters != NULL)
        return 0;

    cipher->set_asn1_parameters = set_asn1_parameters;
    return 1;
}

int UCI_CIPHER_meth_set_get_asn1_params(UCI_CIPHER *cipher,
                                        int (*get_asn1_parameters) (UCI_CIPHER_CTX *,
                                                                    ASN1_TYPE *))
{
    if (cipher->get_asn1_parameters != NULL)
        return 0;

    cipher->get_asn1_parameters = get_asn1_parameters;
    return 1;
}

int UCI_CIPHER_meth_set_ctrl(UCI_CIPHER *cipher,
                             int (*ctrl) (UCI_CIPHER_CTX *, int type,
                                          int arg, void *ptr))
{
    if (cipher->ctrl != NULL)
        return 0;

    cipher->ctrl = ctrl;
    return 1;
}


int (*UCI_CIPHER_meth_get_init(const UCI_CIPHER *cipher))(UCI_CIPHER_CTX *ctx,
                                                          const unsigned char *key,
                                                          const unsigned char *iv,
                                                          int enc)
{
    return cipher->init;
}
int (*UCI_CIPHER_meth_get_do_cipher(const UCI_CIPHER *cipher))(UCI_CIPHER_CTX *ctx,
                                                               unsigned char *out,
                                                               const unsigned char *in,
                                                               size_t inl)
{
    return cipher->do_cipher;
}

int (*UCI_CIPHER_meth_get_cleanup(const UCI_CIPHER *cipher))(UCI_CIPHER_CTX *)
{
    return cipher->cleanup;
}

int (*UCI_CIPHER_meth_get_set_asn1_params(const UCI_CIPHER *cipher))(UCI_CIPHER_CTX *,
                                                                     ASN1_TYPE *)
{
    return cipher->set_asn1_parameters;
}

int (*UCI_CIPHER_meth_get_get_asn1_params(const UCI_CIPHER *cipher))(UCI_CIPHER_CTX *,
                                                               ASN1_TYPE *)
{
    return cipher->get_asn1_parameters;
}

int (*UCI_CIPHER_meth_get_ctrl(const UCI_CIPHER *cipher))(UCI_CIPHER_CTX *,
                                                          int type, int arg,
                                                          void *ptr)
{
    return cipher->ctrl;
}

