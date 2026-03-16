#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "uci/sdf.h"

#define DEFAULT_PQ_ALGID  ((ULONG)0x00F0D502u)
#define DEFAULT_PQ_ALG    "mlkem768"

static ULONG parse_algid_env(const char *name, ULONG fallback)
{
    const char *v = getenv(name);
    char *end = NULL;
    unsigned long x;

    if (v == NULL || v[0] == '\0')
        return fallback;

    errno = 0;
    x = strtoul(v, &end, 0);
    if (errno != 0 || end == v || (end != NULL && *end != '\0') || x > 0xFFFFFFFFul)
        return fallback;

    return (ULONG)x;
}

static int write_patch_file(const char *path, ULONG algid,
                            const char *alg, const char *provider)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return 0;
    fprintf(fp, "0x%08X %s provider=%s\n", algid, alg, provider);
    fclose(fp);
    return 1;
}

static int test_rsa(HANDLE sess)
{
    LONG rc;
    RSArefPublicKey pub;
    BYTE enc[4096];
    ULONG enc_len = sizeof(enc);
    HANDLE imported = NULL;

    rc = SDF_ExportEncPublicKey_RSA(sess, 1, &pub);
    if (rc != SDR_OK)
        return 0;

    rc = SDF_GenerateKeyWithEPK(sess, 128, SGD_RSA, &pub, enc, &enc_len, &imported);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] RSA prepare enc rc=0x%08X\n", (unsigned)rc);
        return 0;
    }
    (void)SDF_DestroyKey(sess, imported);
    imported = NULL;

    rc = SDF_ImportKeyWithISK(sess, 1, SGD_RSA, NULL, enc, enc_len, &imported);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] unified ISK RSA rc=0x%08X\n", (unsigned)rc);
        return 0;
    }

    (void)SDF_DestroyKey(sess, imported);
    printf("[PASS] unified ISK RSA ok, enc_len=%u\n", (unsigned)enc_len);
    return 1;
}

static int test_ecc(HANDLE sess)
{
    LONG rc;
    ECCrefPublicKey pub;
    ULONG enc_len;
    BYTE *enc = NULL;
    HANDLE imported = NULL;

    rc = SDF_ExportEncPublicKey_ECC(sess, 1, &pub);
    if (rc != SDR_OK)
        return 0;

    enc_len = (ULONG)sizeof(ECCCipher) + ((128u + 7u) / 8u) - 1u;
    enc = (BYTE *)calloc(1, enc_len);
    if (enc == NULL)
        return 0;

    rc = SDF_GenerateKeyWithEPK(sess, 128, SGD_SM2_3, &pub, enc, &enc_len, &imported);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] ECC prepare enc rc=0x%08X\n", (unsigned)rc);
        free(enc);
        return 0;
    }
    (void)SDF_DestroyKey(sess, imported);
    imported = NULL;

    rc = SDF_ImportKeyWithISK(sess, 1, SGD_SM2_3, NULL, enc, enc_len, &imported);
    free(enc);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] unified ISK ECC rc=0x%08X\n", (unsigned)rc);
        return 0;
    }

    (void)SDF_DestroyKey(sess, imported);
    printf("[PASS] unified ISK ECC ok, enc_len=%u\n", (unsigned)enc_len);
    return 1;
}

static int test_pq(HANDLE sess)
{
    const char *provider = getenv("UCI_TEST_PROVIDER");
    const char *pq_alg = getenv("UCI_TEST_KEM_ALG");
    ULONG pq_algid = parse_algid_env("UCI_TEST_KEM_ALGID", DEFAULT_PQ_ALGID);
    const char *patch_file = "/tmp/sdf_isk_unified_patch.conf";
    char props[256];
    HANDLE prov = NULL;
    HANDLE pub = NULL;
    HANDLE sk = NULL;
    HANDLE imported = NULL;
    BYTE *ct = NULL;
    ULONG ct_len = 0;
    BYTE ss_dec[8192];
    ULONG ss_dec_len = sizeof(ss_dec);
    LONG rc;

    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;

    if (provider == NULL || provider[0] == '\0')
        provider = "oqsprovider";
    if (pq_alg == NULL || pq_alg[0] == '\0')
        pq_alg = DEFAULT_PQ_ALG;

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props))
        return 0;

    if (!write_patch_file(patch_file, pq_algid, pq_alg, provider))
        return 0;
    setenv("SDFR_PATCH_FILE", patch_file, 1);

    rc = SDFU_LoadProvider(sess, (const CHAR *)provider, &prov);
    if (rc != SDR_OK) {
        unlink(patch_file);
        return 0;
    }

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)pq_alg, (const CHAR *)props, &sk);
    if (rc != SDR_OK) {
        SDFU_UnloadProvider(prov);
        unlink(patch_file);
        return 0;
    }

    {
        BYTE *pub_blob = NULL;
        ULONG pub_blob_len = 0;

        rc = SDFU_ExportPublicKey(sess, sk, NULL, &pub_blob_len);
        if (rc != SDR_OK || pub_blob_len == 0) {
            fprintf(stderr, "[FAIL] export pq pub-len rc=0x%08X len=%u\n", (unsigned)rc, (unsigned)pub_blob_len);
            goto pq_cleanup;
        }

        pub_blob = (BYTE *)malloc(pub_blob_len);
        if (pub_blob == NULL) {
            fprintf(stderr, "[FAIL] alloc pq pub_blob len=%u\n", (unsigned)pub_blob_len);
            rc = SDR_NOBUFFER;
            goto pq_cleanup;
        }

        rc = SDFU_ExportPublicKey(sess, sk, pub_blob, &pub_blob_len);
        if (rc != SDR_OK) {
            fprintf(stderr, "[FAIL] export pq pub rc=0x%08X len=%u\n", (unsigned)rc, (unsigned)pub_blob_len);
            free(pub_blob);
            goto pq_cleanup;
        }

        rc = SDFU_ImportPublicKey(sess, pub_blob, pub_blob_len,
                                  (const CHAR *)props, &pub);
        free(pub_blob);
        if (rc != SDR_OK) {
            fprintf(stderr, "[FAIL] import pq pub rc=0x%08X len=%u\n", (unsigned)rc, (unsigned)pub_blob_len);
            goto pq_cleanup;
        }
    }

    rc = SDF_GenerateKeyWithEPK(sess, 256, pq_algid, pub, NULL, &ct_len, &imported);
    if (rc != SDR_OUTARGERR || ct_len == 0)
        goto pq_cleanup;
    ct = (BYTE *)malloc(ct_len);
    if (ct == NULL) { rc = SDR_NOBUFFER; goto pq_cleanup; }
    rc = SDF_GenerateKeyWithEPK(sess, 256, pq_algid, pub, ct, &ct_len, &imported);
    if (rc != SDR_OK)
        goto pq_cleanup;
    (void)SDF_DestroyKey(sess, imported);
    imported = NULL;

    rc = SDF_ImportKeyWithISK(sess, 0, pq_algid, sk,
                              ct, ct_len, &imported);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] unified ISK PQ rc=0x%08X\n", (unsigned)rc);
        goto pq_cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_DECAPSULATE;
    req.uiAlgID = pq_algid;
    req.hKeyHandle = sk;
    req.pucExtraInput = ct;
    req.uiExtraInputLength = ct_len;
    rsp.pucOutput = ss_dec;
    rsp.puiOutputLength = &ss_dec_len;
    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK || ss_dec_len == 0)
        goto pq_cleanup;

    {
        BYTE zero_iv[16] = {0};
        BYTE enc[8192];
        ULONG enc_len = sizeof(enc);
        BYTE dec[8192];
        ULONG dec_len = sizeof(dec);

        SDFU_SYM_REQUEST reqs;
        SDFU_SYM_RESPONSE rsps;

        memset(&reqs, 0, sizeof(reqs));
        memset(&rsps, 0, sizeof(rsps));
        reqs.uiOperation = SDFU_SYM_OP_ENCRYPT;
        reqs.pucAlgorithm = (const CHAR *)"SM4-CBC";
        reqs.hKeyHandle = imported;
        reqs.pucIV = zero_iv;
        reqs.uiIVLength = sizeof(zero_iv);
        reqs.pucInput = ss_dec;
        reqs.uiInputLength = ss_dec_len;
        rsps.pucOutput = enc;
        rsps.puiOutputLength = &enc_len;
        rc = SDFU_ExecuteSymmetric(sess, &reqs, &rsps);
        if (rc != SDR_OK)
            goto pq_cleanup;

        memset(&reqs, 0, sizeof(reqs));
        memset(&rsps, 0, sizeof(rsps));
        reqs.uiOperation = SDFU_SYM_OP_DECRYPT;
        reqs.pucAlgorithm = (const CHAR *)"SM4-CBC";
        reqs.hKeyHandle = imported;
        reqs.pucIV = zero_iv;
        reqs.uiIVLength = sizeof(zero_iv);
        reqs.pucInput = enc;
        reqs.uiInputLength = enc_len;
        rsps.pucOutput = dec;
        rsps.puiOutputLength = &dec_len;
        rc = SDFU_ExecuteSymmetric(sess, &reqs, &rsps);
        if (rc != SDR_OK)
            goto pq_cleanup;

        if (dec_len != ss_dec_len || memcmp(dec, ss_dec, ss_dec_len) != 0) {
            rc = SDR_VERIFYERR;
            goto pq_cleanup;
        }
    }

    printf("[PASS] unified ISK PQ ok alg=%s(0x%08X) ct_len=%u ss_len=%u\n",
           pq_alg, (unsigned)pq_algid, (unsigned)ct_len, (unsigned)ss_dec_len);

pq_cleanup:
    if (imported)
        (void)SDF_DestroyKey(sess, imported);
    if (pub)
        (void)SDF_DestroyKey(sess, pub);
    if (sk)
        (void)SDF_DestroyKey(sess, sk);
    if (ct)
        free(ct);
    if (prov)
        (void)SDFU_UnloadProvider(prov);
    unlink(patch_file);

    return (rc == SDR_OK);
}

int main(void)
{
    HANDLE dev = NULL;
    HANDLE sess = NULL;
    LONG rc;
    int ok_rsa, ok_ecc, ok_pq;

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK)
        return 2;

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        SDF_CloseDevice(dev);
        return 2;
    }

    ok_rsa = test_rsa(sess);
    ok_ecc = test_ecc(sess);
    ok_pq = test_pq(sess);

    SDF_CloseSession(sess);
    SDF_CloseDevice(dev);

    if (ok_rsa && ok_ecc && ok_pq) {
        printf("[PASS] unified ISK: RSA+ECC+PQ all passed\n");
        return 0;
    }

    fprintf(stderr, "[FAIL] unified ISK summary rsa=%d ecc=%d pq=%d\n", ok_rsa, ok_ecc, ok_pq);
    return 1;
}
