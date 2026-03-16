#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "uci/sdf.h"

static void print_sha256_hex(const char *tag, const BYTE *buf, ULONG len)
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    size_t i;

    if (buf == NULL || len == 0) {
        printf("[HASH] %s sha256=NA len=%u\n", tag, (unsigned)len);
        return;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        printf("[HASH] %s sha256=ERR len=%u\n", tag, (unsigned)len);
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, buf, (size_t)len) != 1 ||
        EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        EVP_MD_CTX_free(ctx);
        printf("[HASH] %s sha256=ERR len=%u\n", tag, (unsigned)len);
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
    LONG rc_old, rc_new;
    RSArefPublicKey old_pub;
    RSArefPublicKey new_pub;
    ULONG new_len = sizeof(new_pub);

    memset(&old_pub, 0, sizeof(old_pub));
    memset(&new_pub, 0, sizeof(new_pub));

    rc_old = SDF_ExportSignPublicKey_RSA(sess, 1, &old_pub);
    rc_new = SDF_ExportSignPublicKey(sess, SGD_RSA, 1, (BYTE *)&new_pub, &new_len);

    if (rc_old != SDR_OK || rc_new != SDR_OK) {
        fprintf(stderr, "[FAIL] RSA export old=0x%08X new=0x%08X\n", (unsigned)rc_old, (unsigned)rc_new);
        return 0;
    }
    if (new_len != sizeof(new_pub)) {
        fprintf(stderr, "[FAIL] RSA new_len=%u expect=%zu\n", (unsigned)new_len, sizeof(new_pub));
        return 0;
    }
    if (memcmp(&old_pub, &new_pub, sizeof(old_pub)) != 0) {
        fprintf(stderr, "[FAIL] RSA old/new mismatch\n");
        return 0;
    }

    print_sha256_hex("ExportSign.RSA", (const BYTE *)&new_pub, (ULONG)sizeof(new_pub));
    printf("[PASS] ExportSign RSA unified matches legacy\n");
    return 1;
}

static int test_ecc(HANDLE sess)
{
    LONG rc_old, rc_new;
    ECCrefPublicKey old_pub;
    ECCrefPublicKey new_pub;
    ULONG new_len = sizeof(new_pub);

    memset(&old_pub, 0, sizeof(old_pub));
    memset(&new_pub, 0, sizeof(new_pub));

    rc_old = SDF_ExportSignPublicKey_ECC(sess, 1, &old_pub);
    rc_new = SDF_ExportSignPublicKey(sess, SGD_SM2_3, 1, (BYTE *)&new_pub, &new_len);

    if (rc_old != SDR_OK || rc_new != SDR_OK) {
        fprintf(stderr, "[FAIL] ECC export old=0x%08X new=0x%08X\n", (unsigned)rc_old, (unsigned)rc_new);
        return 0;
    }
    if (new_len != sizeof(new_pub)) {
        fprintf(stderr, "[FAIL] ECC new_len=%u expect=%zu\n", (unsigned)new_len, sizeof(new_pub));
        return 0;
    }
    if (memcmp(&old_pub, &new_pub, sizeof(old_pub)) != 0) {
        fprintf(stderr, "[FAIL] ECC old/new mismatch\n");
        return 0;
    }

    print_sha256_hex("ExportSign.ECC", (const BYTE *)&new_pub, (ULONG)sizeof(new_pub));
    printf("[PASS] ExportSign ECC unified matches legacy\n");
    return 1;
}

int main(void)
{
    HANDLE dev = NULL;
    HANDLE sess = NULL;
    LONG rc;
    int ok_rsa = 0;
    int ok_ecc = 0;

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] open device rc=0x%08X\n", (unsigned)rc);
        return 1;
    }

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] open session rc=0x%08X\n", (unsigned)rc);
        (void)SDF_CloseDevice(dev);
        return 1;
    }

    ok_rsa = test_rsa(sess);
    ok_ecc = test_ecc(sess);

    (void)SDF_CloseSession(sess);
    (void)SDF_CloseDevice(dev);

    if (ok_rsa && ok_ecc) {
        printf("[PASS] ExportSign unified: RSA+ECC all passed\n");
        return 0;
    }

    fprintf(stderr, "[FAIL] ExportSign unified summary rsa=%d ecc=%d\n", ok_rsa, ok_ecc);
    return 1;
}
