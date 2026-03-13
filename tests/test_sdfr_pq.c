#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uci/sdf.h"

#define TEST_ALGID_MLDSA ((ULONG)0x00F0D501u)
#define TEST_ALGID_MLKEM ((ULONG)0x00F0D502u)

static int write_patch_file(const char *path, const char *provider)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return 0;

    /* format: <algid> <algorithm> <properties> */
    fprintf(fp, "0x%08X mldsa65 provider=%s\n", TEST_ALGID_MLDSA, provider);
    fprintf(fp, "0x%08X mlkem768 provider=%s\n", TEST_ALGID_MLKEM, provider);

    fclose(fp);
    return 1;
}

static void print_rc(const char *step, LONG rc)
{
    fprintf(stderr, "[FAIL] %s rc=0x%08X\n", step, (unsigned int)rc);
}

int main(int argc, char **argv)
{
    const char *provider = getenv("UCI_TEST_PROVIDER");
    const char *patch_file = "/tmp/sdfr_pq_patch.conf";
    char props[256];

    HANDLE dev = NULL;
    HANDLE sess = NULL;
    HANDLE prov = NULL;
    HANDLE sign_key = NULL;
    HANDLE kem_key = NULL;

    LONG rc;
    int exit_code = 1;

    const unsigned char msg[] = "sdf-route-sign-kem-smoke";

    unsigned char *sig = NULL;
    ULONG sig_len = 0;

    unsigned char *ct = NULL;
    ULONG ct_len = 0;

    unsigned char *ss1 = NULL;
    ULONG ss1_len = 0;

    unsigned char *ss2 = NULL;
    ULONG ss2_len = 0;

    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;

    if (provider == NULL || provider[0] == '\0')
        provider = (argc > 1) ? argv[1] : "myoqsprov";

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props)) {
        fprintf(stderr, "[FAIL] provider name too long\n");
        return 2;
    }

    if (!write_patch_file(patch_file, provider)) {
        fprintf(stderr, "[FAIL] write patch file failed: %s\n", patch_file);
        return 2;
    }
    setenv("SDFR_PATCH_FILE", patch_file, 1);

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) {
        print_rc("SDF_OpenDevice", rc);
        goto cleanup;
    }

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        print_rc("SDF_OpenSession", rc);
        goto cleanup;
    }

    rc = SDFU_LoadProvider(sess, (const CHAR *)provider, &prov);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] provider '%s' load failed (rc=0x%08X). "
                "Build/install provider first, then rerun.\n",
                provider, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    /* ML-DSA sign/verify */
    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)"mldsa65", (const CHAR *)props, &sign_key);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] generate mldsa65 key failed (rc=0x%08X). "
                "Provider may not expose mldsa65.\n",
                (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_SIGN;
    req.uiAlgID = TEST_ALGID_MLDSA;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);

    rsp.puiOutputLength = &sig_len;
    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK || sig_len == 0) {
        print_rc("SDFR_Execute SIGN(size)", rc);
        goto cleanup;
    }

    sig = (unsigned char *)malloc(sig_len);
    if (sig == NULL) {
        fprintf(stderr, "[FAIL] malloc sig failed\n");
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_SIGN;
    req.uiAlgID = TEST_ALGID_MLDSA;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);

    rsp.pucOutput = sig;
    rsp.puiOutputLength = &sig_len;
    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK) {
        print_rc("SDFR_Execute SIGN", rc);
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_VERIFY;
    req.uiAlgID = TEST_ALGID_MLDSA;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);
    req.pucExtraInput = sig;
    req.uiExtraInputLength = sig_len;

    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK || rsp.lVerifyResult != 1) {
        fprintf(stderr, "[FAIL] VERIFY rc=0x%08X verify=%ld\n", (unsigned int)rc, (long)rsp.lVerifyResult);
        goto cleanup;
    }

    /* ML-KEM encapsulate/decapsulate */
    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)"mlkem768", (const CHAR *)props, &kem_key);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] generate mlkem768 key failed (rc=0x%08X). "
                "Provider may not expose mlkem768.\n",
                (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = TEST_ALGID_MLKEM;
    req.hKeyHandle = kem_key;

    rsp.puiOutputLength = &ss1_len;
    rsp.puiExtraOutputLength = &ct_len;
    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK || ss1_len == 0 || ct_len == 0) {
        print_rc("SDFR_Execute KEM_ENCAPSULATE(size)", rc);
        goto cleanup;
    }

    ss1 = (unsigned char *)malloc(ss1_len);
    ct = (unsigned char *)malloc(ct_len);
    if (ss1 == NULL || ct == NULL) {
        fprintf(stderr, "[FAIL] malloc kem buffers failed\n");
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = TEST_ALGID_MLKEM;
    req.hKeyHandle = kem_key;

    rsp.pucOutput = ss1;
    rsp.puiOutputLength = &ss1_len;
    rsp.pucExtraOutput = ct;
    rsp.puiExtraOutputLength = &ct_len;
    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK) {
        print_rc("SDFR_Execute KEM_ENCAPSULATE", rc);
        goto cleanup;
    }

    ss2 = (unsigned char *)malloc(ss1_len);
    if (ss2 == NULL) {
        fprintf(stderr, "[FAIL] malloc ss2 failed\n");
        goto cleanup;
    }
    ss2_len = ss1_len;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_DECAPSULATE;
    req.uiAlgID = TEST_ALGID_MLKEM;
    req.hKeyHandle = kem_key;
    req.pucExtraInput = ct;
    req.uiExtraInputLength = ct_len;

    rsp.pucOutput = ss2;
    rsp.puiOutputLength = &ss2_len;
    rc = SDFR_Execute(sess, &req, &rsp);
    if (rc != SDR_OK) {
        print_rc("SDFR_Execute KEM_DECAPSULATE", rc);
        goto cleanup;
    }

    if (ss1_len != ss2_len || memcmp(ss1, ss2, ss1_len) != 0) {
        fprintf(stderr, "[FAIL] shared secret mismatch: enc_len=%u dec_len=%u\n",
                (unsigned int)ss1_len, (unsigned int)ss2_len);
        goto cleanup;
    }

    printf("[PASS] SDFR ML-DSA sign/verify + ML-KEM encap/decap via provider=%s\n", provider);
    exit_code = 0;

cleanup:
    if (sign_key != NULL && sess != NULL)
        (void)SDF_DestroyKey(sess, sign_key);
    if (kem_key != NULL && sess != NULL)
        (void)SDF_DestroyKey(sess, kem_key);
    if (prov != NULL)
        (void)SDFU_UnloadProvider(prov);
    if (sess != NULL)
        (void)SDF_CloseSession(sess);
    if (dev != NULL)
        (void)SDF_CloseDevice(dev);

    free(sig);
    free(ct);
    free(ss1);
    free(ss2);

    unlink(patch_file);
    return exit_code;
}
