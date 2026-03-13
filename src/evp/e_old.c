/*
 * Copyright 2004-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>

#include <openssl/evp.h>

/*
 * Define some deprecated functions, so older programs don't crash and burn
 * too quickly.  On Windows and VMS, these will never be used, since
 * functions and variables in shared libraries are selected by entry point
 * location, not by name.
 */

#ifndef OPENSSL_NO_BF
# undef UCI_bf_cfb
const UCI_CIPHER *UCI_bf_cfb(void);
const UCI_CIPHER *UCI_bf_cfb(void)
{
    return UCI_bf_cfb64();
}
#endif

#ifndef OPENSSL_NO_DES
# undef UCI_des_cfb
const UCI_CIPHER *UCI_des_cfb(void);
const UCI_CIPHER *UCI_des_cfb(void)
{
    return UCI_des_cfb64();
}

# undef UCI_des_ede3_cfb
const UCI_CIPHER *UCI_des_ede3_cfb(void);
const UCI_CIPHER *UCI_des_ede3_cfb(void)
{
    return UCI_des_ede3_cfb64();
}

# undef UCI_des_ede_cfb
const UCI_CIPHER *UCI_des_ede_cfb(void);
const UCI_CIPHER *UCI_des_ede_cfb(void)
{
    return UCI_des_ede_cfb64();
}
#endif

#ifndef OPENSSL_NO_IDEA
# undef UCI_idea_cfb
const UCI_CIPHER *UCI_idea_cfb(void);
const UCI_CIPHER *UCI_idea_cfb(void)
{
    return UCI_idea_cfb64();
}
#endif

#ifndef OPENSSL_NO_RC2
# undef UCI_rc2_cfb
const UCI_CIPHER *UCI_rc2_cfb(void);
const UCI_CIPHER *UCI_rc2_cfb(void)
{
    return UCI_rc2_cfb64();
}
#endif

#ifndef OPENSSL_NO_CAST
# undef UCI_cast5_cfb
const UCI_CIPHER *UCI_cast5_cfb(void);
const UCI_CIPHER *UCI_cast5_cfb(void)
{
    return UCI_cast5_cfb64();
}
#endif

#ifndef OPENSSL_NO_RC5
# undef UCI_rc5_32_12_16_cfb
const UCI_CIPHER *UCI_rc5_32_12_16_cfb(void);
const UCI_CIPHER *UCI_rc5_32_12_16_cfb(void)
{
    return UCI_rc5_32_12_16_cfb64();
}
#endif

#undef UCI_aes_128_cfb
const UCI_CIPHER *UCI_aes_128_cfb(void);
const UCI_CIPHER *UCI_aes_128_cfb(void)
{
    return UCI_aes_128_cfb128();
}

#undef UCI_aes_192_cfb
const UCI_CIPHER *UCI_aes_192_cfb(void);
const UCI_CIPHER *UCI_aes_192_cfb(void)
{
    return UCI_aes_192_cfb128();
}

#undef UCI_aes_256_cfb
const UCI_CIPHER *UCI_aes_256_cfb(void);
const UCI_CIPHER *UCI_aes_256_cfb(void)
{
    return UCI_aes_256_cfb128();
}
