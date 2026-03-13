/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
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

void openssl_add_all_ciphers_int(void)
{

#ifndef OPENSSL_NO_DES
    UCI_add_cipher(UCI_des_cfb());
    UCI_add_cipher(UCI_des_cfb1());
    UCI_add_cipher(UCI_des_cfb8());
    UCI_add_cipher(UCI_des_ede_cfb());
    UCI_add_cipher(UCI_des_ede3_cfb());
    UCI_add_cipher(UCI_des_ede3_cfb1());
    UCI_add_cipher(UCI_des_ede3_cfb8());

    UCI_add_cipher(UCI_des_ofb());
    UCI_add_cipher(UCI_des_ede_ofb());
    UCI_add_cipher(UCI_des_ede3_ofb());

    UCI_add_cipher(UCI_desx_cbc());
    UCI_add_cipher_alias(SN_desx_cbc, "DESX");
    UCI_add_cipher_alias(SN_desx_cbc, "desx");

    UCI_add_cipher(UCI_des_cbc());
    UCI_add_cipher_alias(SN_des_cbc, "DES");
    UCI_add_cipher_alias(SN_des_cbc, "des");
    UCI_add_cipher(UCI_des_ede_cbc());
    UCI_add_cipher(UCI_des_ede3_cbc());
    UCI_add_cipher_alias(SN_des_ede3_cbc, "DES3");
    UCI_add_cipher_alias(SN_des_ede3_cbc, "des3");

    UCI_add_cipher(UCI_des_ecb());
    UCI_add_cipher(UCI_des_ede());
    UCI_add_cipher_alias(SN_des_ede_ecb, "DES-EDE-ECB");
    UCI_add_cipher_alias(SN_des_ede_ecb, "des-ede-ecb");
    UCI_add_cipher(UCI_des_ede3());
    UCI_add_cipher_alias(SN_des_ede3_ecb, "DES-EDE3-ECB");
    UCI_add_cipher_alias(SN_des_ede3_ecb, "des-ede3-ecb");
    UCI_add_cipher(UCI_des_ede3_wrap());
    UCI_add_cipher_alias(SN_id_smime_alg_CMS3DESwrap, "des3-wrap");
#endif

#ifndef OPENSSL_NO_RC4
    UCI_add_cipher(UCI_rc4());
    UCI_add_cipher(UCI_rc4_40());
# ifndef OPENSSL_NO_MD5
    UCI_add_cipher(UCI_rc4_hmac_md5());
# endif
#endif

#ifndef OPENSSL_NO_IDEA
    UCI_add_cipher(UCI_idea_ecb());
    UCI_add_cipher(UCI_idea_cfb());
    UCI_add_cipher(UCI_idea_ofb());
    UCI_add_cipher(UCI_idea_cbc());
    UCI_add_cipher_alias(SN_idea_cbc, "IDEA");
    UCI_add_cipher_alias(SN_idea_cbc, "idea");
#endif

#ifndef OPENSSL_NO_SEED
    UCI_add_cipher(UCI_seed_ecb());
    UCI_add_cipher(UCI_seed_cfb());
    UCI_add_cipher(UCI_seed_ofb());
    UCI_add_cipher(UCI_seed_cbc());
    UCI_add_cipher_alias(SN_seed_cbc, "SEED");
    UCI_add_cipher_alias(SN_seed_cbc, "seed");
#endif

#ifndef OPENSSL_NO_SM4
    UCI_add_cipher(UCI_sm4_ecb());
    UCI_add_cipher(UCI_sm4_cbc());
    UCI_add_cipher(UCI_sm4_cfb());
    UCI_add_cipher(UCI_sm4_ofb());
    UCI_add_cipher(UCI_sm4_ctr());
    UCI_add_cipher_alias(SN_sm4_cbc, "SM4");
    UCI_add_cipher_alias(SN_sm4_cbc, "sm4");
#endif

#ifndef OPENSSL_NO_RC2
    UCI_add_cipher(UCI_rc2_ecb());
    UCI_add_cipher(UCI_rc2_cfb());
    UCI_add_cipher(UCI_rc2_ofb());
    UCI_add_cipher(UCI_rc2_cbc());
    UCI_add_cipher(UCI_rc2_40_cbc());
    UCI_add_cipher(UCI_rc2_64_cbc());
    UCI_add_cipher_alias(SN_rc2_cbc, "RC2");
    UCI_add_cipher_alias(SN_rc2_cbc, "rc2");
    UCI_add_cipher_alias(SN_rc2_cbc, "rc2-128");
    UCI_add_cipher_alias(SN_rc2_64_cbc, "rc2-64");
    UCI_add_cipher_alias(SN_rc2_40_cbc, "rc2-40");
#endif

#ifndef OPENSSL_NO_BF
    UCI_add_cipher(UCI_bf_ecb());
    UCI_add_cipher(UCI_bf_cfb());
    UCI_add_cipher(UCI_bf_ofb());
    UCI_add_cipher(UCI_bf_cbc());
    UCI_add_cipher_alias(SN_bf_cbc, "BF");
    UCI_add_cipher_alias(SN_bf_cbc, "bf");
    UCI_add_cipher_alias(SN_bf_cbc, "blowfish");
#endif

#ifndef OPENSSL_NO_CAST
    UCI_add_cipher(UCI_cast5_ecb());
    UCI_add_cipher(UCI_cast5_cfb());
    UCI_add_cipher(UCI_cast5_ofb());
    UCI_add_cipher(UCI_cast5_cbc());
    UCI_add_cipher_alias(SN_cast5_cbc, "CAST");
    UCI_add_cipher_alias(SN_cast5_cbc, "cast");
    UCI_add_cipher_alias(SN_cast5_cbc, "CAST-cbc");
    UCI_add_cipher_alias(SN_cast5_cbc, "cast-cbc");
#endif

#ifndef OPENSSL_NO_RC5
    UCI_add_cipher(UCI_rc5_32_12_16_ecb());
    UCI_add_cipher(UCI_rc5_32_12_16_cfb());
    UCI_add_cipher(UCI_rc5_32_12_16_ofb());
    UCI_add_cipher(UCI_rc5_32_12_16_cbc());
    UCI_add_cipher_alias(SN_rc5_cbc, "rc5");
    UCI_add_cipher_alias(SN_rc5_cbc, "RC5");
#endif

    UCI_add_cipher(UCI_aes_128_ecb());
    UCI_add_cipher(UCI_aes_128_cbc());
    UCI_add_cipher(UCI_aes_128_cfb());
    UCI_add_cipher(UCI_aes_128_cfb1());
    UCI_add_cipher(UCI_aes_128_cfb8());
    UCI_add_cipher(UCI_aes_128_ofb());
    UCI_add_cipher(UCI_aes_128_ctr());
    UCI_add_cipher(UCI_aes_128_gcm());
#ifndef OPENSSL_NO_OCB
    UCI_add_cipher(UCI_aes_128_ocb());
#endif
    UCI_add_cipher(UCI_aes_128_xts());
    UCI_add_cipher(UCI_aes_128_ccm());
    UCI_add_cipher(UCI_aes_128_wrap());
    UCI_add_cipher_alias(SN_id_aes128_wrap, "aes128-wrap");
    UCI_add_cipher(UCI_aes_128_wrap_pad());
    UCI_add_cipher_alias(SN_id_aes128_wrap_pad, "aes128-wrap-pad");
    UCI_add_cipher_alias(SN_aes_128_cbc, "AES128");
    UCI_add_cipher_alias(SN_aes_128_cbc, "aes128");
    UCI_add_cipher(UCI_aes_192_ecb());
    UCI_add_cipher(UCI_aes_192_cbc());
    UCI_add_cipher(UCI_aes_192_cfb());
    UCI_add_cipher(UCI_aes_192_cfb1());
    UCI_add_cipher(UCI_aes_192_cfb8());
    UCI_add_cipher(UCI_aes_192_ofb());
    UCI_add_cipher(UCI_aes_192_ctr());
    UCI_add_cipher(UCI_aes_192_gcm());
#ifndef OPENSSL_NO_OCB
    UCI_add_cipher(UCI_aes_192_ocb());
#endif
    UCI_add_cipher(UCI_aes_192_ccm());
    UCI_add_cipher(UCI_aes_192_wrap());
    UCI_add_cipher_alias(SN_id_aes192_wrap, "aes192-wrap");
    UCI_add_cipher(UCI_aes_192_wrap_pad());
    UCI_add_cipher_alias(SN_id_aes192_wrap_pad, "aes192-wrap-pad");
    UCI_add_cipher_alias(SN_aes_192_cbc, "AES192");
    UCI_add_cipher_alias(SN_aes_192_cbc, "aes192");
    UCI_add_cipher(UCI_aes_256_ecb());
    UCI_add_cipher(UCI_aes_256_cbc());
    UCI_add_cipher(UCI_aes_256_cfb());
    UCI_add_cipher(UCI_aes_256_cfb1());
    UCI_add_cipher(UCI_aes_256_cfb8());
    UCI_add_cipher(UCI_aes_256_ofb());
    UCI_add_cipher(UCI_aes_256_ctr());
    UCI_add_cipher(UCI_aes_256_gcm());
#ifndef OPENSSL_NO_OCB
    UCI_add_cipher(UCI_aes_256_ocb());
#endif
    UCI_add_cipher(UCI_aes_256_xts());
    UCI_add_cipher(UCI_aes_256_ccm());
    UCI_add_cipher(UCI_aes_256_wrap());
    UCI_add_cipher_alias(SN_id_aes256_wrap, "aes256-wrap");
    UCI_add_cipher(UCI_aes_256_wrap_pad());
    UCI_add_cipher_alias(SN_id_aes256_wrap_pad, "aes256-wrap-pad");
    UCI_add_cipher_alias(SN_aes_256_cbc, "AES256");
    UCI_add_cipher_alias(SN_aes_256_cbc, "aes256");
    UCI_add_cipher(UCI_aes_128_cbc_hmac_sha1());
    UCI_add_cipher(UCI_aes_256_cbc_hmac_sha1());
    UCI_add_cipher(UCI_aes_128_cbc_hmac_sha256());
    UCI_add_cipher(UCI_aes_256_cbc_hmac_sha256());
#ifndef OPENSSL_NO_ARIA
    UCI_add_cipher(UCI_aria_128_ecb());
    UCI_add_cipher(UCI_aria_128_cbc());
    UCI_add_cipher(UCI_aria_128_cfb());
    UCI_add_cipher(UCI_aria_128_cfb1());
    UCI_add_cipher(UCI_aria_128_cfb8());
    UCI_add_cipher(UCI_aria_128_ctr());
    UCI_add_cipher(UCI_aria_128_ofb());
    UCI_add_cipher(UCI_aria_128_gcm());
    UCI_add_cipher(UCI_aria_128_ccm());
    UCI_add_cipher_alias(SN_aria_128_cbc, "ARIA128");
    UCI_add_cipher_alias(SN_aria_128_cbc, "aria128");
    UCI_add_cipher(UCI_aria_192_ecb());
    UCI_add_cipher(UCI_aria_192_cbc());
    UCI_add_cipher(UCI_aria_192_cfb());
    UCI_add_cipher(UCI_aria_192_cfb1());
    UCI_add_cipher(UCI_aria_192_cfb8());
    UCI_add_cipher(UCI_aria_192_ctr());
    UCI_add_cipher(UCI_aria_192_ofb());
    UCI_add_cipher(UCI_aria_192_gcm());
    UCI_add_cipher(UCI_aria_192_ccm());
    UCI_add_cipher_alias(SN_aria_192_cbc, "ARIA192");
    UCI_add_cipher_alias(SN_aria_192_cbc, "aria192");
    UCI_add_cipher(UCI_aria_256_ecb());
    UCI_add_cipher(UCI_aria_256_cbc());
    UCI_add_cipher(UCI_aria_256_cfb());
    UCI_add_cipher(UCI_aria_256_cfb1());
    UCI_add_cipher(UCI_aria_256_cfb8());
    UCI_add_cipher(UCI_aria_256_ctr());
    UCI_add_cipher(UCI_aria_256_ofb());
    UCI_add_cipher(UCI_aria_256_gcm());
    UCI_add_cipher(UCI_aria_256_ccm());
    UCI_add_cipher_alias(SN_aria_256_cbc, "ARIA256");
    UCI_add_cipher_alias(SN_aria_256_cbc, "aria256");
#endif

#ifndef OPENSSL_NO_CAMELLIA
    UCI_add_cipher(UCI_camellia_128_ecb());
    UCI_add_cipher(UCI_camellia_128_cbc());
    UCI_add_cipher(UCI_camellia_128_cfb());
    UCI_add_cipher(UCI_camellia_128_cfb1());
    UCI_add_cipher(UCI_camellia_128_cfb8());
    UCI_add_cipher(UCI_camellia_128_ofb());
    UCI_add_cipher_alias(SN_camellia_128_cbc, "CAMELLIA128");
    UCI_add_cipher_alias(SN_camellia_128_cbc, "camellia128");
    UCI_add_cipher(UCI_camellia_192_ecb());
    UCI_add_cipher(UCI_camellia_192_cbc());
    UCI_add_cipher(UCI_camellia_192_cfb());
    UCI_add_cipher(UCI_camellia_192_cfb1());
    UCI_add_cipher(UCI_camellia_192_cfb8());
    UCI_add_cipher(UCI_camellia_192_ofb());
    UCI_add_cipher_alias(SN_camellia_192_cbc, "CAMELLIA192");
    UCI_add_cipher_alias(SN_camellia_192_cbc, "camellia192");
    UCI_add_cipher(UCI_camellia_256_ecb());
    UCI_add_cipher(UCI_camellia_256_cbc());
    UCI_add_cipher(UCI_camellia_256_cfb());
    UCI_add_cipher(UCI_camellia_256_cfb1());
    UCI_add_cipher(UCI_camellia_256_cfb8());
    UCI_add_cipher(UCI_camellia_256_ofb());
    UCI_add_cipher_alias(SN_camellia_256_cbc, "CAMELLIA256");
    UCI_add_cipher_alias(SN_camellia_256_cbc, "camellia256");
    UCI_add_cipher(UCI_camellia_128_ctr());
    UCI_add_cipher(UCI_camellia_192_ctr());
    UCI_add_cipher(UCI_camellia_256_ctr());
#endif

#ifndef OPENSSL_NO_CHACHA
    UCI_add_cipher(UCI_chacha20());
# ifndef OPENSSL_NO_POLY1305
    UCI_add_cipher(UCI_chacha20_poly1305());
# endif
#endif
}
