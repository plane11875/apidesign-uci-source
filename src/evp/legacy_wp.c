/*
 * Copyright 2005-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Whirlpool low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/whrlpool.h>
#include "crypto/evp.h"
#include "legacy_meth.h"

IMPLEMENT_LEGACY_UCI_MD_METH(wp, WHIRLPOOL)

static const UCI_MD whirlpool_md = {
    NID_whirlpool,
    0,
    WHIRLPOOL_DIGEST_LENGTH,
    0,
    UCI_ORIG_GLOBAL,
    LEGACY_UCI_MD_METH_TABLE(wp_init, wp_update, wp_final, NULL,
                             WHIRLPOOL_BBLOCK / 8),
};

const UCI_MD *UCI_whirlpool(void)
{
    return &whirlpool_md;
}
