/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include "crypto/evp.h"
#include <openssl/pkcs12.h>
#include <openssl/objects.h>

void openssl_add_all_digests_int(void)
{
#ifndef OPENSSL_NO_MD4
    UCI_add_digest(UCI_md4());
#endif
#ifndef OPENSSL_NO_MD5
    UCI_add_digest(UCI_md5());
    UCI_add_digest_alias(SN_md5, "ssl3-md5");
    UCI_add_digest(UCI_md5_sha1());
#endif
    UCI_add_digest(UCI_sha1());
    UCI_add_digest_alias(SN_sha1, "ssl3-sha1");
    UCI_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA);
#if !defined(OPENSSL_NO_MDC2) && !defined(OPENSSL_NO_DES)
    UCI_add_digest(UCI_mdc2());
#endif
#ifndef OPENSSL_NO_RMD160
    UCI_add_digest(UCI_ripemd160());
    UCI_add_digest_alias(SN_ripemd160, "ripemd");
    UCI_add_digest_alias(SN_ripemd160, "rmd160");
#endif
    UCI_add_digest(UCI_sha224());
    UCI_add_digest(UCI_sha256());
    UCI_add_digest(UCI_sha384());
    UCI_add_digest(UCI_sha512());
    UCI_add_digest(UCI_sha512_224());
    UCI_add_digest(UCI_sha512_256());
#ifndef OPENSSL_NO_WHIRLPOOL
    UCI_add_digest(UCI_whirlpool());
#endif
#ifndef OPENSSL_NO_SM3
    UCI_add_digest(UCI_sm3());
#endif
#ifndef OPENSSL_NO_BLAKE2
    UCI_add_digest(UCI_blake2b512());
    UCI_add_digest(UCI_blake2s256());
#endif
    UCI_add_digest(UCI_sha3_224());
    UCI_add_digest(UCI_sha3_256());
    UCI_add_digest(UCI_sha3_384());
    UCI_add_digest(UCI_sha3_512());
    UCI_add_digest(UCI_shake128());
    UCI_add_digest(UCI_shake256());
}
