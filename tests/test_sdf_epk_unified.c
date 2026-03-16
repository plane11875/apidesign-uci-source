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
    HANDLE key = NULL;
    BYTE out[4096];
    ULONG out_len = sizeof(out);

    rc = SDF_ExportEncPublicKey_RSA(sess, 1, &pub);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] RSA export pub rc=0x%08X\n", (unsigned)rc);
        return 0;
    }

    fprintf(stderr, "[DBG] call unified RSA\n");
    rc = SDF_GenerateKeyWithEPK(sess, 128, SGD_RSA, &pub, out, &out_len, &key);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] unified EPK RSA rc=0x%08X\n", (unsigned)rc);
        return 0;
    }

    if (out_len == 0 || key == NULL) {
        fprintf(stderr, "[FAIL] unified EPK RSA empty output\n");
        return 0;
    }

    (void)SDF_DestroyKey(sess, key);
    printf("[PASS] unified EPK RSA ok, out_len=%u\n", (unsigned)out_len);
    return 1;
}

static int test_ecc(HANDLE sess)
{
    LONG rc;
    ECCrefPublicKey pub;
    HANDLE key = NULL;
    ULONG session_len = (128u + 7u) / 8u;
    ULONG out_len = (ULONG)sizeof(ECCCipher) + session_len - 1u;
    BYTE *out = (BYTE *)calloc(1, out_len);

    rc = SDF_ExportEncPublicKey_ECC(sess, 1, &pub);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] ECC export pub rc=0x%08X\n", (unsigned)rc);
        return 0;
    }

    fprintf(stderr, "[DBG] call unified ECC\n");
    if (out == NULL) {
        fprintf(stderr, "[FAIL] ECC alloc failed\n");
        return 0;
    }

    rc = SDF_GenerateKeyWithEPK(sess, 128, SGD_SM2_3, &pub,
                                out, &out_len, &key);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] unified EPK ECC rc=0x%08X\n", (unsigned)rc);
        return 0;
    }

    if (out_len == 0 || key == NULL) {
        fprintf(stderr, "[FAIL] unified EPK ECC invalid output len=%u\n", (unsigned)out_len);
        free(out);
        return 0;
    }

    (void)SDF_DestroyKey(sess, key);
    free(out);
    printf("[PASS] unified EPK ECC ok, out_len=%u\n", (unsigned)out_len);
    return 1;
}

static int test_pq(HANDLE sess)
{
    const char *provider = getenv("UCI_TEST_PROVIDER");
    const char *pq_alg = getenv("UCI_TEST_KEM_ALG");
    ULONG pq_algid = parse_algid_env("UCI_TEST_KEM_ALGID", DEFAULT_PQ_ALGID);
    const char *patch_file = "/tmp/sdf_epk_unified_patch.conf";
    char props[256];
    HANDLE prov = NULL;
    HANDLE pub = NULL;
    HANDLE sk = NULL;
    HANDLE imported = NULL;
    BYTE ct[8192];
    ULONG ct_len = sizeof(ct);
    BYTE ss_dec[8192];
    ULONG ss_dec_len = sizeof(ss_dec);
    LONG rc;

    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;

    if (provider == NULL || provider[0] == '\0')
        provider = "myoqsprov";
    if (pq_alg == NULL || pq_alg[0] == '\0')
        pq_alg = DEFAULT_PQ_ALG;

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props))
        return 0;

    if (!write_patch_file(patch_file, pq_algid, pq_alg, provider)) {
        fprintf(stderr, "[FAIL] write patch file failed\n");
        return 0;
    }
    setenv("SDFR_PATCH_FILE", patch_file, 1);

    rc = SDFU_LoadProvider(sess, (const CHAR *)provider, &prov);
    if (rc != SDR_OK) {
        fprintf(stderr, "[SKIP] provider %s load rc=0x%08X\n", provider, (unsigned)rc);
        unlink(patch_file);
        return 0;
    }

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)pq_alg, (const CHAR *)props, &sk);
    if (rc != SDR_OK) {
        fprintf(stderr, "[SKIP] generate pq key rc=0x%08X\n", (unsigned)rc);
        SDFU_UnloadProvider(prov);
        unlink(patch_file);
        return 0;
    }

    {
        BYTE pub_blob[8192];
        ULONG pub_blob_len = sizeof(pub_blob);
        rc = SDFU_ExportPublicKey(sess, sk, pub_blob, &pub_blob_len);
        if (rc != SDR_OK) {
            fprintf(stderr, "[FAIL] export pq pub rc=0x%08X\n", (unsigned)rc);
            goto pq_cleanup;
        }
        rc = SDFU_ImportPublicKey(sess, pub_blob, pub_blob_len,
                                  (const CHAR *)props, &pub);
        if (rc != SDR_OK) {
            fprintf(stderr, "[FAIL] import pq pub rc=0x%08X\n", (unsigned)rc);
            goto pq_cleanup;
        }
    }

    fprintf(stderr, "[DBG] call unified PQ\n");
    rc = SDF_GenerateKeyWithEPK(sess, 256, pq_algid, pub,
                                ct, &ct_len, &imported);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] unified EPK PQ rc=0x%08X\n", (unsigned)rc);
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
    if (rc != SDR_OK || ss_dec_len == 0) {
        fprintf(stderr, "[FAIL] SDFR decap rc=0x%08X\n", (unsigned)rc);
        goto pq_cleanup;
    }

    {
        BYTE zero_iv[16] = {0};
        BYTE enc[8192];
        ULONG enc_len = sizeof(enc);
        BYTE dec[8192];
        ULONG dec_len = sizeof(dec);

        {
            SDFU_SYM_REQUEST sym_req;
            SDFU_SYM_RESPONSE sym_rsp;
            memset(&sym_req, 0, sizeof(sym_req));
            memset(&sym_rsp, 0, sizeof(sym_rsp));
            sym_req.uiOperation = SDFU_SYM_OP_ENCRYPT;
            sym_req.pucAlgorithm = (const CHAR *)"SM4-CBC";
            sym_req.hKeyHandle = imported;
            sym_req.pucIV = zero_iv;
            sym_req.uiIVLength = sizeof(zero_iv);
            sym_req.pucInput = ss_dec;
            sym_req.uiInputLength = ss_dec_len;
            sym_rsp.pucOutput = enc;
            sym_rsp.puiOutputLength = &enc_len;
            rc = SDFU_ExecuteSymmetric(sess, &sym_req, &sym_rsp);
        }
        if (rc != SDR_OK) {
            fprintf(stderr, "[FAIL] imported key encrypt rc=0x%08X\n", (unsigned)rc);
            goto pq_cleanup;
        }

        {
            SDFU_SYM_REQUEST sym_req;
            SDFU_SYM_RESPONSE sym_rsp;
            memset(&sym_req, 0, sizeof(sym_req));
            memset(&sym_rsp, 0, sizeof(sym_rsp));
            sym_req.uiOperation = SDFU_SYM_OP_DECRYPT;
            sym_req.pucAlgorithm = (const CHAR *)"SM4-CBC";
            sym_req.hKeyHandle = imported;
            sym_req.pucIV = zero_iv;
            sym_req.uiIVLength = sizeof(zero_iv);
            sym_req.pucInput = enc;
            sym_req.uiInputLength = enc_len;
            sym_rsp.pucOutput = dec;
            sym_rsp.puiOutputLength = &dec_len;
            rc = SDFU_ExecuteSymmetric(sess, &sym_req, &sym_rsp);
        }
        if (rc != SDR_OK) {
            fprintf(stderr, "[FAIL] imported key decrypt rc=0x%08X\n", (unsigned)rc);
            goto pq_cleanup;
        }

        if (dec_len != ss_dec_len || memcmp(dec, ss_dec, ss_dec_len) != 0) {
            fprintf(stderr, "[FAIL] imported key self-check mismatch\n");
            rc = SDR_VERIFYERR;
            goto pq_cleanup;
        }
    }

    printf("[PASS] unified EPK PQ ok alg=%s(0x%08X) ct_len=%u ss_len=%u\n",
           pq_alg, (unsigned)pq_algid, (unsigned)ct_len, (unsigned)ss_dec_len);

pq_cleanup:
    if (imported)
        (void)SDF_DestroyKey(sess, imported);
    if (pub)
        (void)SDF_DestroyKey(sess, pub);
    if (sk)
        (void)SDF_DestroyKey(sess, sk);
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
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_OpenDevice rc=0x%08X\n", (unsigned)rc);
        return 2;
    }

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_OpenSession rc=0x%08X\n", (unsigned)rc);
        SDF_CloseDevice(dev);
        return 2;
    }

    ok_rsa = test_rsa(sess);
    ok_ecc = test_ecc(sess);
    ok_pq = test_pq(sess);

    SDF_CloseSession(sess);
    SDF_CloseDevice(dev);

    if (ok_rsa && ok_ecc && ok_pq) {
        printf("[PASS] unified EPK: RSA+ECC+PQ all passed\n");
        return 0;
    }

    fprintf(stderr, "[FAIL] unified EPK summary rsa=%d ecc=%d pq=%d\n",
            ok_rsa, ok_ecc, ok_pq);
    return 1;
}
