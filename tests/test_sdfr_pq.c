#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "uci/sdf.h"

#define DEFAULT_SIGN_ALGID ((ULONG)0x00F0D501u)
#define DEFAULT_KEM_ALGID  ((ULONG)0x00F0D502u)
#define DEFAULT_SIGN_ALG   "mldsa65"
#define DEFAULT_KEM_ALG    "mlkem768"

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

static int write_patch_file(const char *path,
                            ULONG sign_algid,
                            const char *sign_alg,
                            ULONG kem_algid,
                            const char *kem_alg,
                            const char *provider)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return 0;

    /* format: <algid> <algorithm> <properties> */
    fprintf(fp, "0x%08X %s provider=%s\n", sign_algid, sign_alg, provider);
    fprintf(fp, "0x%08X %s provider=%s\n", kem_algid, kem_alg, provider);

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
    const char *sign_alg = getenv("UCI_TEST_SIGN_ALG");
    const char *kem_alg = getenv("UCI_TEST_KEM_ALG");
    ULONG sign_algid = parse_algid_env("UCI_TEST_SIGN_ALGID", DEFAULT_SIGN_ALGID);
    ULONG kem_algid = parse_algid_env("UCI_TEST_KEM_ALGID", DEFAULT_KEM_ALGID);

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
    if (sign_alg == NULL || sign_alg[0] == '\0')
        sign_alg = DEFAULT_SIGN_ALG;
    if (kem_alg == NULL || kem_alg[0] == '\0')
        kem_alg = DEFAULT_KEM_ALG;

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props)) {
        fprintf(stderr, "[FAIL] provider name too long\n");
        return 2;
    }

    if (!write_patch_file(patch_file, sign_algid, sign_alg, kem_algid, kem_alg, provider)) {
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
                "[SKIP] provider '%s' load failed (rc=0x%08X). Build/install provider first, then rerun.\n",
                provider, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    /* sign/verify */
    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)sign_alg, (const CHAR *)props, &sign_key);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] generate %s key failed (rc=0x%08X). Provider may not expose this sign alg.\n",
                sign_alg, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_SIGN;
    req.uiAlgID = sign_algid;
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
    req.uiAlgID = sign_algid;
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
    req.uiAlgID = sign_algid;
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

    /* kem encapsulate/decapsulate */
    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)kem_alg, (const CHAR *)props, &kem_key);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] generate %s key failed (rc=0x%08X). Provider may not expose this KEM alg.\n",
                kem_alg, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = kem_algid;
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
    req.uiAlgID = kem_algid;
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
    req.uiAlgID = kem_algid;
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

    printf("[PASS] SDFR sign/verify(%s,0x%08X) + KEM(%s,0x%08X) via provider=%s\n",
           sign_alg, (unsigned int)sign_algid,
           kem_alg, (unsigned int)kem_algid,
           provider);
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
