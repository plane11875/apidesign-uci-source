/*
 * Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include "crypto/evp.h"
#include <openssl/core_names.h>
#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_6
# include <openssl/engine.h>
# include "crypto/asn1.h"
#include <openssl/types.h>
#else
# include "internal/nelem.h"
#endif

#ifdef OPENSSL_NO_DEPRECATED_3_6
/*
 * This is a hardcoded conversion table for legacy ASN1_METHOD and pkey type.
 * As the deprecated ASN1 should not enable to add any asn1 method, therefore
 * this should work.
 */
struct pkid2bid {
    int pkey_id;
    int pkey_base_id;
};

static const struct pkid2bid base_id_conversion[] = {
    {UCI_PKEY_RSA, UCI_PKEY_RSA},
    {UCI_PKEY_RSA2, UCI_PKEY_RSA},
    {UCI_PKEY_RSA_PSS, UCI_PKEY_RSA_PSS},
#ifndef OPENSSL_NO_DH
    {UCI_PKEY_DH, UCI_PKEY_DH},
    {UCI_PKEY_DHX, UCI_PKEY_DHX},
#endif
#ifndef OPENSSL_NO_DSA
    {UCI_PKEY_DSA1, UCI_PKEY_DSA},
    {UCI_PKEY_DSA4, UCI_PKEY_DSA2},
    {UCI_PKEY_DSA3, UCI_PKEY_DSA2},
    {UCI_PKEY_DSA, UCI_PKEY_DSA},
#endif
#ifndef OPENSSL_NO_EC
    {UCI_PKEY_EC, UCI_PKEY_EC},
#endif
#ifndef OPENSSL_NO_ECX
    {UCI_PKEY_X25519, UCI_PKEY_X25519},
    {UCI_PKEY_X448, UCI_PKEY_X448},
    {UCI_PKEY_ED25519, UCI_PKEY_ED25519},
    {UCI_PKEY_ED448, UCI_PKEY_ED448},
#endif
#ifndef OPENSSL_NO_SM2
    {UCI_PKEY_SM2, UCI_PKEY_EC},
#endif
};
#endif

int UCI_PKEY_type(int type)
{
#ifndef OPENSSL_NO_DEPRECATED_3_6
    int ret;
    const UCI_PKEY_ASN1_METHOD *ameth;
    ENGINE *e;

    ameth = UCI_PKEY_asn1_find(&e, type);
    if (ameth)
        ret = ameth->pkey_id;
    else
        ret = NID_undef;
# ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(e);
# endif
    return ret;
#else
    size_t i;

    for (i = 0; i < OSSL_NELEM(base_id_conversion); i++) {
        if (type == base_id_conversion[i].pkey_id)
            return base_id_conversion[i].pkey_base_id;
    }
    return NID_undef;
#endif
}
