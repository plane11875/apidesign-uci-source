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

int main(void)
{
    HANDLE dev = NULL, sess = NULL;
    LONG rc;
    BYTE msg[] = "internal-op-unified-rsa";

    BYTE old_pub_out[4096], new_pub_out[4096];
    ULONG old_pub_len = sizeof(old_pub_out), new_pub_len = sizeof(new_pub_out);

    BYTE old_prv_out[4096], new_prv_out[4096];
    ULONG old_prv_len = sizeof(old_prv_out), new_prv_len = sizeof(new_prv_out);

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) return 1;
    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) { SDF_CloseDevice(dev); return 1; }

    rc = SDF_InternalPublicKeyOperation_RSA(sess, 1,
                                            msg, (ULONG)strlen((char*)msg),
                                            old_pub_out, &old_pub_len);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] old internal pub op rc=0x%08X\n", (unsigned)rc);
        goto fail;
    }

    rc = SDF_InternalPublicKeyOperation(sess, SGD_RSA, 1, NULL,
                                        msg, (ULONG)strlen((char*)msg),
                                        new_pub_out, &new_pub_len);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] new internal pub op rc=0x%08X\n", (unsigned)rc);
        goto fail;
    }

    /* RSA 公钥运算输出可能因随机填充不同，不能按密文字节比较。
     * 改为验证“旧/新私钥运算都能把各自密文还原为同一明文”。 */

    rc = SDF_InternalPrivateKeyOperation_RSA(sess, 1,
                                             old_pub_out, old_pub_len,
                                             old_prv_out, &old_prv_len);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] old internal private op(old_ct) rc=0x%08X\n", (unsigned)rc);
        goto fail;
    }

    rc = SDF_InternalPrivateKeyOperation(sess, SGD_RSA, 1, NULL,
                                         old_pub_out, old_pub_len,
                                         new_prv_out, &new_prv_len);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] new internal private op(old_ct) rc=0x%08X\n", (unsigned)rc);
        goto fail;
    }

    if (old_prv_len != new_prv_len || memcmp(old_prv_out, new_prv_out, old_prv_len) != 0) {
        fprintf(stderr, "[FAIL] private op parity mismatch on old_ct\n");
        goto fail;
    }

    if (old_prv_len != (ULONG)strlen((char*)msg) || memcmp(old_prv_out, msg, old_prv_len) != 0) {
        fprintf(stderr, "[FAIL] roundtrip plaintext mismatch on old_ct\n");
        goto fail;
    }

    /* 再验证 new_ct 也可被旧/新私钥运算一致还原 */
    old_prv_len = sizeof(old_prv_out);
    new_prv_len = sizeof(new_prv_out);

    rc = SDF_InternalPrivateKeyOperation_RSA(sess, 1,
                                             new_pub_out, new_pub_len,
                                             old_prv_out, &old_prv_len);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] old internal private op(new_ct) rc=0x%08X\n", (unsigned)rc);
        goto fail;
    }

    rc = SDF_InternalPrivateKeyOperation(sess, SGD_RSA, 1, NULL,
                                         new_pub_out, new_pub_len,
                                         new_prv_out, &new_prv_len);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] new internal private op(new_ct) rc=0x%08X\n", (unsigned)rc);
        goto fail;
    }

    if (old_prv_len != new_prv_len || memcmp(old_prv_out, new_prv_out, old_prv_len) != 0) {
        fprintf(stderr, "[FAIL] private op parity mismatch on new_ct\n");
        goto fail;
    }

    if (new_prv_len != (ULONG)strlen((char*)msg) || memcmp(new_prv_out, msg, new_prv_len) != 0) {
        fprintf(stderr, "[FAIL] roundtrip plaintext mismatch on new_ct\n");
        goto fail;
    }

    print_sha256_hex("InternalPublicOp.RSA", new_pub_out, new_pub_len);
    print_sha256_hex("InternalPrivateOp.RSA", new_prv_out, new_prv_len);
    printf("[PASS] unified internal public/private RSA operations match legacy\n");

    SDF_CloseSession(sess);
    SDF_CloseDevice(dev);
    return 0;

fail:
    SDF_CloseSession(sess);
    SDF_CloseDevice(dev);
    return 1;
}
