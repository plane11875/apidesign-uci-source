#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uci/sdf.h"

#define DEFAULT_PROVIDER  "myoqsprov"
#define DEFAULT_SIGN_ALG  "mldsa65"
#define DEFAULT_KEM_ALG   "mlkem768"

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return fallback;
    return v;
}

static void print_fail(const char *step, LONG rc)
{
    fprintf(stderr, "[FAIL] %s rc=0x%08X\n", step, (unsigned int)rc);
}

int main(void)
{
    const char *provider = env_or("UCI_TEST_PROVIDER", DEFAULT_PROVIDER);
    const char *sign_alg = env_or("UCI_TEST_SIGN_ALG", DEFAULT_SIGN_ALG);
    const char *kem_alg = env_or("UCI_TEST_KEM_ALG", DEFAULT_KEM_ALG);

    char props[256];

    HANDLE dev = NULL;
    HANDLE sess = NULL;
    HANDLE prov = NULL;
    HANDLE sign_key = NULL;
    HANDLE kem_key = NULL;

    LONG rc;
    int exit_code = 1;

    const BYTE msg[] = "sdfu-myoqsprov-sign-verify";

    BYTE *sig = NULL;
    ULONG sig_len = 0;

    BYTE *ct = NULL;
    ULONG ct_len = 0;

    BYTE *ss1 = NULL;
    ULONG ss1_len = 0;

    BYTE *ss2 = NULL;
    ULONG ss2_len = 0;

    SDFU_ASYM_REQUEST req;
    SDFU_ASYM_RESPONSE rsp;

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props)) {
        fprintf(stderr, "[FAIL] provider name too long\n");
        return 2;
    }

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) {
        print_fail("SDF_OpenDevice", rc);
        return 2;
    }

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        print_fail("SDF_OpenSession", rc);
        goto cleanup;
    }

    rc = SDFU_LoadProvider(sess, (const CHAR *)provider, &prov);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] provider '%s' load failed rc=0x%08X (check OPENSSL_MODULES)\n",
                provider, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)sign_alg, (const CHAR *)props, &sign_key);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] generate sign key '%s' failed rc=0x%08X\n",
                sign_alg, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFU_ASYM_OP_SIGN;
    req.pucAlgorithm = NULL;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);

    rsp.puiOutputLength = &sig_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    if (rc != SDR_OK || sig_len == 0) {
        print_fail("SDFU_ExecuteAsymmetric SIGN(size)", rc);
        goto cleanup;
    }

    sig = (BYTE *)malloc(sig_len);
    if (sig == NULL) {
        fprintf(stderr, "[FAIL] malloc sig failed\n");
        goto cleanup;
    }

    memset(&rsp, 0, sizeof(rsp));
    rsp.pucOutput = sig;
    rsp.puiOutputLength = &sig_len;

    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    if (rc != SDR_OK) {
        print_fail("SDFU_ExecuteAsymmetric SIGN", rc);
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFU_ASYM_OP_VERIFY;
    req.pucAlgorithm = NULL;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);
    req.pucExtraInput = sig;
    req.uiExtraInputLength = sig_len;

    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    if (rc != SDR_OK || rsp.lVerifyResult != 1) {
        fprintf(stderr, "[FAIL] VERIFY rc=0x%08X verify=%ld\n", (unsigned int)rc, (long)rsp.lVerifyResult);
        goto cleanup;
    }

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)kem_alg, (const CHAR *)props, &kem_key);
    if (rc != SDR_OK) {
        fprintf(stderr,
                "[SKIP] generate KEM key '%s' failed rc=0x%08X\n",
                kem_alg, (unsigned int)rc);
        exit_code = 77;
        goto cleanup;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFU_ASYM_OP_KEM_ENCAPSULATE;
    req.pucAlgorithm = NULL;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = kem_key;

    rsp.puiOutputLength = &ss1_len;
    rsp.puiExtraOutputLength = &ct_len;

    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    if (rc != SDR_OK || ss1_len == 0 || ct_len == 0) {
        print_fail("SDFU_ExecuteAsymmetric KEM_ENCAPSULATE(size)", rc);
        goto cleanup;
    }

    ss1 = (BYTE *)malloc(ss1_len);
    ct = (BYTE *)malloc(ct_len);
    if (ss1 == NULL || ct == NULL) {
        fprintf(stderr, "[FAIL] malloc KEM buffers failed\n");
        goto cleanup;
    }

    memset(&rsp, 0, sizeof(rsp));
    rsp.pucOutput = ss1;
    rsp.puiOutputLength = &ss1_len;
    rsp.pucExtraOutput = ct;
    rsp.puiExtraOutputLength = &ct_len;

    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    if (rc != SDR_OK) {
        print_fail("SDFU_ExecuteAsymmetric KEM_ENCAPSULATE", rc);
        goto cleanup;
    }

    ss2 = (BYTE *)malloc(ss1_len);
    if (ss2 == NULL) {
        fprintf(stderr, "[FAIL] malloc ss2 failed\n");
        goto cleanup;
    }
    ss2_len = ss1_len;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFU_ASYM_OP_KEM_DECAPSULATE;
    req.pucAlgorithm = NULL;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = kem_key;
    req.pucExtraInput = ct;
    req.uiExtraInputLength = ct_len;

    rsp.pucOutput = ss2;
    rsp.puiOutputLength = &ss2_len;

    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    if (rc != SDR_OK) {
        print_fail("SDFU_ExecuteAsymmetric KEM_DECAPSULATE", rc);
        goto cleanup;
    }

    if (ss1_len != ss2_len || memcmp(ss1, ss2, ss1_len) != 0) {
        fprintf(stderr, "[FAIL] shared secret mismatch: enc_len=%u dec_len=%u\n",
                (unsigned int)ss1_len, (unsigned int)ss2_len);
        goto cleanup;
    }

    printf("[PASS] SDFU sign/verify(%s) + KEM(%s) via provider=%s\n",
           sign_alg, kem_alg, provider);
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

    return exit_code;
}
