#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "uci/sdf.h"

static void print_sha256_hex(const char *tag, const BYTE *buf, ULONG len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    size_t i;

    if (ctx == NULL || buf == NULL || len == 0 ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, buf, (size_t)len) != 1 ||
        EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        printf("[HASH] %s sha256=ERR len=%u\n", tag, (unsigned)len);
        if (ctx)
            EVP_MD_CTX_free(ctx);
        return;
    }

    printf("[HASH] %s sha256=", tag);
    for (i = 0; i < (size_t)md_len; ++i)
        printf("%02x", md[i]);
    printf(" len=%u\n", (unsigned)len);
    EVP_MD_CTX_free(ctx);
}

static int test_rsa(HANDLE sess)
{
    LONG rc;
    RSArefPublicKey rsa_pub;
    BYTE msg[] = "unified-rsa-op-sign-verify";

    BYTE op_old[4096], op_new[4096];
    ULONG op_old_len = sizeof(op_old), op_new_len = sizeof(op_new);

    BYTE sig[8192];
    ULONG sig_len = sizeof(sig);

    memset(&rsa_pub, 0, sizeof(rsa_pub));
    rc = SDF_ExportSignPublicKey_RSA(sess, 1, &rsa_pub);
    if (rc != SDR_OK)
        return 0;

    rc = SDF_ExternalPublicKeyOperation_RSA(sess, &rsa_pub,
                                            msg, (ULONG)strlen((char*)msg),
                                            op_old, &op_old_len);
    if (rc != SDR_OK)
        return 0;

    rc = SDF_ExternalPublicKeyOperation(sess, SGD_RSA, SDFR_OP_PKEY_ENCRYPT,
                                        &rsa_pub,
                                        msg, (ULONG)strlen((char*)msg),
                                        op_new, &op_new_len);
    if (rc != SDR_OK)
        return 0;

    {
        BYTE dec_old[4096], dec_new[4096];
        ULONG dec_old_len = sizeof(dec_old), dec_new_len = sizeof(dec_new);

        rc = SDF_InternalPrivateKeyOperation_RSA(sess, 1, op_old, op_old_len,
                                                 dec_old, &dec_old_len);
        if (rc != SDR_OK)
            return 0;

        rc = SDF_InternalPrivateKeyOperation_RSA(sess, 1, op_new, op_new_len,
                                                 dec_new, &dec_new_len);
        if (rc != SDR_OK)
            return 0;

        if (dec_old_len != (ULONG)strlen((char*)msg) ||
            dec_new_len != (ULONG)strlen((char*)msg) ||
            memcmp(dec_old, msg, dec_old_len) != 0 ||
            memcmp(dec_new, msg, dec_new_len) != 0) {
            fprintf(stderr, "[FAIL] RSA external public op decrypt mismatch\n");
            return 0;
        }
    }

    rc = SDF_InternalSign(sess, SGD_RSA, 1, NULL,
                          msg, (ULONG)strlen((char*)msg),
                          sig, &sig_len);
    if (rc != SDR_OK || sig_len == 0)
        return 0;

    rc = SDF_InternalVerify(sess, SGD_RSA, 1, NULL,
                            msg, (ULONG)strlen((char*)msg),
                            sig, sig_len);
    if (rc != SDR_OK)
        return 0;

    print_sha256_hex("RSA.external_op", op_new, op_new_len);
    print_sha256_hex("RSA.sig", sig, sig_len);
    printf("[PASS] unified RSA op/sign/verify baseline ok\n");
    return 1;
}

static int test_ecc(HANDLE sess)
{
    LONG rc;
    ECCrefPublicKey ecc_pub;
    BYTE msg[] = "unified-ecc-op-sign-verify";

    ULONG c_old_len = (ULONG)sizeof(ECCCipher) + (ULONG)strlen((char*)msg) - 1u;
    ULONG c_new_len = c_old_len;
    BYTE *c_old = (BYTE *)calloc(1, c_old_len);
    BYTE *c_new = (BYTE *)calloc(1, c_new_len);

    BYTE s_new[sizeof(ECCSignature)];
    ULONG s_new_len = sizeof(s_new);

    if (!c_old || !c_new)
        return 0;

    memset(&ecc_pub, 0, sizeof(ecc_pub));
    rc = SDF_ExportSignPublicKey_ECC(sess, 1, &ecc_pub);
    if (rc != SDR_OK)
        goto fail;

    rc = SDF_ExternalEncrypt_ECC(sess, SGD_SM2_3, &ecc_pub,
                                 msg, (ULONG)strlen((char*)msg),
                                 (ECCCipher *)c_old);
    if (rc != SDR_OK)
        goto fail;

    rc = SDF_ExternalPublicKeyOperation(sess, SGD_SM2_3, SDFR_OP_PKEY_ENCRYPT,
                                        &ecc_pub,
                                        msg, (ULONG)strlen((char*)msg),
                                        c_new, &c_new_len);
    if (rc != SDR_OK)
        goto fail;

    if (c_new_len != c_old_len || memcmp(c_old, c_new, c_old_len) != 0) {
        fprintf(stderr, "[FAIL] ECC external op mismatch\n");
        goto fail;
    }

    rc = SDF_InternalSign(sess, SGD_SM2_3, 1, NULL,
                          msg, (ULONG)strlen((char*)msg),
                          s_new, &s_new_len);
    if (rc != SDR_OK || s_new_len != sizeof(ECCSignature))
        goto fail;

    rc = SDF_InternalVerify(sess, SGD_SM2_3, 1, NULL,
                            msg, (ULONG)strlen((char*)msg),
                            s_new, s_new_len);
    if (rc != SDR_OK)
        goto fail;

    rc = SDF_ExternalVerify(sess, SGD_SM2_3, &ecc_pub,
                            msg, (ULONG)strlen((char*)msg),
                            s_new, s_new_len);
    if (rc != SDR_OK)
        goto fail;

    print_sha256_hex("ECC.external_op", c_new, c_new_len);
    print_sha256_hex("ECC.sig", s_new, s_new_len);
    printf("[PASS] unified ECC op/sign/verify baseline ok\n");
    free(c_old);
    free(c_new);
    return 1;

fail:
    free(c_old);
    free(c_new);
    return 0;
}

int main(void)
{
    HANDLE dev = NULL;
    HANDLE sess = NULL;
    LONG rc;
    int ok_rsa = 0, ok_ecc = 0;

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) return 1;
    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) { SDF_CloseDevice(dev); return 1; }

    ok_rsa = test_rsa(sess);
    ok_ecc = test_ecc(sess);

    SDF_CloseSession(sess);
    SDF_CloseDevice(dev);

    if (ok_rsa && ok_ecc) {
        printf("[PASS] unified op/sign/verify: RSA+ECC all passed\n");
        return 0;
    }

    fprintf(stderr, "[FAIL] unified op/sign/verify summary rsa=%d ecc=%d\n", ok_rsa, ok_ecc);
    return 1;
}
