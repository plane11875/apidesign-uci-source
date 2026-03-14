#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "uci/sdf.h"

typedef struct {
    const char *name;
    const char *key_alg;
    const char *sign_digest;
    int keygen_ok;
    int export_import_ok;
    int sign_verify_internal_ok;
    int sign_verify_external_ok;
    int encdec_internal_ok;
    int encdec_external_ok;

    LONG rc_keygen;
    LONG rc_export;
    LONG rc_import;
    LONG rc_sign;
    LONG rc_verify_internal;
    LONG rc_verify_external;
    LONG rc_enc_internal;
    LONG rc_dec_internal;
    LONG rc_enc_external;
    LONG rc_dec_external;
} CASE_RESULT;

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0')
        return fallback;
    return v;
}

static void print_rc(const char *step, LONG rc)
{
    printf("  - %-34s rc=0x%08X\n", step, (unsigned int)rc);
}

static int do_export_import_public(HANDLE sess,
                                   HANDLE internal_key,
                                   const char *props,
                                   HANDLE *out_external_pub,
                                   LONG *rc_export,
                                   LONG *rc_import)
{
    LONG rc;
    BYTE *pub = NULL;
    ULONG pub_len = 0;

    *out_external_pub = NULL;

    rc = SDFU_ExportPublicKey(sess, internal_key, NULL, &pub_len);
    *rc_export = rc;
    if (rc != SDR_OK || pub_len == 0)
        return 0;

    pub = (BYTE *)malloc(pub_len);
    if (pub == NULL)
        return 0;

    rc = SDFU_ExportPublicKey(sess, internal_key, pub, &pub_len);
    *rc_export = rc;
    if (rc != SDR_OK || pub_len == 0) {
        free(pub);
        return 0;
    }

    rc = SDFU_ImportPublicKey(sess, pub, pub_len, (const CHAR *)props, out_external_pub);
    *rc_import = rc;

    free(pub);
    return rc == SDR_OK && *out_external_pub != NULL;
}

static int do_sign_verify(HANDLE sess,
                          HANDLE sign_key,
                          HANDLE verify_key,
                          const char *digest,
                          const char *props,
                          LONG *rc_sign,
                          LONG *rc_verify)
{
    const BYTE msg[] = "sdfu-rsa-ecc-sign-verify";
    SDFU_ASYM_REQUEST req;
    SDFU_ASYM_RESPONSE rsp;
    BYTE *sig = NULL;
    ULONG sig_len = 0;
    LONG rc;
    int ok = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_SIGN;
    req.pucAlgorithm = (const CHAR *)digest;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);

    rsp.puiOutputLength = &sig_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_sign = rc;
    if (rc != SDR_OK || sig_len == 0)
        goto end;

    sig = (BYTE *)malloc(sig_len);
    if (sig == NULL)
        goto end;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_SIGN;
    req.pucAlgorithm = (const CHAR *)digest;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = sign_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);

    rsp.pucOutput = sig;
    rsp.puiOutputLength = &sig_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_sign = rc;
    if (rc != SDR_OK)
        goto end;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_VERIFY;
    req.pucAlgorithm = (const CHAR *)digest;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = verify_key;
    req.pucInput = msg;
    req.uiInputLength = (ULONG)(sizeof(msg) - 1);
    req.pucExtraInput = sig;
    req.uiExtraInputLength = sig_len;

    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_verify = rc;
    if (rc == SDR_OK && rsp.lVerifyResult == 1)
        ok = 1;

end:
    free(sig);
    return ok;
}

static int do_enc_dec(HANDLE sess,
                      HANDLE encrypt_key,
                      HANDLE decrypt_key,
                      const char *props,
                      LONG *rc_enc,
                      LONG *rc_dec)
{
    const BYTE plain[] = "sdfu-rsa-ecc-enc-dec";
    SDFU_ASYM_REQUEST req;
    SDFU_ASYM_RESPONSE rsp;
    BYTE *cipher = NULL;
    BYTE *plain_out = NULL;
    ULONG cipher_len = 0;
    ULONG plain_out_len = 0;
    LONG rc;
    int ok = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_PKEY_ENCRYPT;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = encrypt_key;
    req.pucInput = plain;
    req.uiInputLength = (ULONG)(sizeof(plain) - 1);

    rsp.puiOutputLength = &cipher_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_enc = rc;
    if (rc != SDR_OK || cipher_len == 0)
        goto end;

    cipher = (BYTE *)malloc(cipher_len);
    if (cipher == NULL)
        goto end;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_PKEY_ENCRYPT;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = encrypt_key;
    req.pucInput = plain;
    req.uiInputLength = (ULONG)(sizeof(plain) - 1);

    rsp.pucOutput = cipher;
    rsp.puiOutputLength = &cipher_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_enc = rc;
    if (rc != SDR_OK || cipher_len == 0)
        goto end;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_PKEY_DECRYPT;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = decrypt_key;
    req.pucInput = cipher;
    req.uiInputLength = cipher_len;

    rsp.puiOutputLength = &plain_out_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_dec = rc;
    if (rc != SDR_OK || plain_out_len == 0)
        goto end;

    plain_out = (BYTE *)malloc(plain_out_len);
    if (plain_out == NULL)
        goto end;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_ASYM_OP_PKEY_DECRYPT;
    req.pucProperties = (const CHAR *)props;
    req.hKeyHandle = decrypt_key;
    req.pucInput = cipher;
    req.uiInputLength = cipher_len;

    rsp.pucOutput = plain_out;
    rsp.puiOutputLength = &plain_out_len;
    rc = SDFU_ExecuteAsymmetric(sess, &req, &rsp);
    *rc_dec = rc;
    if (rc != SDR_OK)
        goto end;

    if (plain_out_len == (ULONG)(sizeof(plain) - 1) &&
        memcmp(plain_out, plain, sizeof(plain) - 1) == 0) {
        ok = 1;
    }

end:
    free(cipher);
    free(plain_out);
    return ok;
}

static void run_case(HANDLE sess, const char *props,
                     const char *key_alg, const char *digest,
                     const char *name, CASE_RESULT *out)
{
    HANDLE internal_key = NULL;
    HANDLE external_pub = NULL;
    LONG rc;

    memset(out, 0, sizeof(*out));
    out->name = name;
    out->key_alg = key_alg;
    out->sign_digest = digest;

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)key_alg, (const CHAR *)props, &internal_key);
    out->rc_keygen = rc;
    if (rc != SDR_OK)
        goto cleanup;

    out->keygen_ok = 1;

    out->export_import_ok = do_export_import_public(sess,
                                                     internal_key,
                                                     props,
                                                     &external_pub,
                                                     &out->rc_export,
                                                     &out->rc_import);

    out->sign_verify_internal_ok = do_sign_verify(sess,
                                                  internal_key,
                                                  internal_key,
                                                  digest,
                                                  props,
                                                  &out->rc_sign,
                                                  &out->rc_verify_internal);

    if (external_pub != NULL) {
        out->sign_verify_external_ok = do_sign_verify(sess,
                                                      internal_key,
                                                      external_pub,
                                                      digest,
                                                      props,
                                                      &out->rc_sign,
                                                      &out->rc_verify_external);
    }

    out->encdec_internal_ok = do_enc_dec(sess,
                                         internal_key,
                                         internal_key,
                                         props,
                                         &out->rc_enc_internal,
                                         &out->rc_dec_internal);

    if (external_pub != NULL) {
        out->encdec_external_ok = do_enc_dec(sess,
                                             external_pub,
                                             internal_key,
                                             props,
                                             &out->rc_enc_external,
                                             &out->rc_dec_external);
    }

cleanup:
    if (external_pub != NULL)
        (void)SDF_DestroyKey(sess, external_pub);
    if (internal_key != NULL)
        (void)SDF_DestroyKey(sess, internal_key);
}

static void print_case(const CASE_RESULT *r)
{
    printf("\n[%s] key_alg=%s digest=%s\n", r->name, r->key_alg, r->sign_digest);

    if (!r->keygen_ok) {
        print_rc("GenerateKeyPair", r->rc_keygen);
        return;
    }

    printf("  - export/import public key            : %s\n", r->export_import_ok ? "OK" : "NO");
    if (!r->export_import_ok) {
        print_rc("ExportPublicKey", r->rc_export);
        print_rc("ImportPublicKey", r->rc_import);
    }

    printf("  - internal priv sign + internal pub verify : %s\n",
           r->sign_verify_internal_ok ? "OK" : "NO");
    if (!r->sign_verify_internal_ok) {
        print_rc("Sign", r->rc_sign);
        print_rc("Verify(internal)", r->rc_verify_internal);
    }

    printf("  - internal priv sign + external pub verify : %s\n",
           r->sign_verify_external_ok ? "OK" : "NO");
    if (!r->sign_verify_external_ok) {
        print_rc("Sign", r->rc_sign);
        print_rc("Verify(external)", r->rc_verify_external);
    }

    printf("  - internal pub encrypt + internal priv decrypt : %s\n",
           r->encdec_internal_ok ? "OK" : "NO");
    if (!r->encdec_internal_ok) {
        print_rc("Encrypt(internal)", r->rc_enc_internal);
        print_rc("Decrypt(internal)", r->rc_dec_internal);
    }

    printf("  - external pub encrypt + internal priv decrypt : %s\n",
           r->encdec_external_ok ? "OK" : "NO");
    if (!r->encdec_external_ok) {
        print_rc("Encrypt(external)", r->rc_enc_external);
        print_rc("Decrypt(internal)", r->rc_dec_external);
    }
}

int main(void)
{
    const char *provider = env_or("UCI_TEST_PROVIDER", "default");
    const char *rsa_alg = env_or("UCI_TEST_RSA_ALG", "RSA");
    const char *ecc_alg = env_or("UCI_TEST_ECC_ALG", "SM2");
    const char *rsa_digest = env_or("UCI_TEST_RSA_DIGEST", "SHA256");
    const char *ecc_digest = env_or("UCI_TEST_ECC_DIGEST", "SM3");

    char props[256];

    HANDLE dev = NULL;
    HANDLE sess = NULL;
    HANDLE prov = NULL;

    LONG rc;

    CASE_RESULT rsa_res;
    CASE_RESULT ecc_res;

    int pass_count = 0;

    if (snprintf(props, sizeof(props), "provider=%s", provider) >= (int)sizeof(props)) {
        fprintf(stderr, "[FAIL] provider name too long\n");
        return 2;
    }

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_OpenDevice rc=0x%08X\n", (unsigned int)rc);
        return 2;
    }

    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDF_OpenSession rc=0x%08X\n", (unsigned int)rc);
        (void)SDF_CloseDevice(dev);
        return 2;
    }

    rc = SDFU_LoadProvider(sess, (const CHAR *)provider, &prov);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] SDFU_LoadProvider(%s) rc=0x%08X\n", provider, (unsigned int)rc);
        (void)SDF_CloseSession(sess);
        (void)SDF_CloseDevice(dev);
        return 2;
    }

    printf("[INFO] provider=%s props=%s\n", provider, props);

    run_case(sess, props, rsa_alg, rsa_digest, "RSA", &rsa_res);
    run_case(sess, props, ecc_alg, ecc_digest, "ECC", &ecc_res);

    print_case(&rsa_res);
    print_case(&ecc_res);

    if (rsa_res.keygen_ok) {
        pass_count += rsa_res.export_import_ok;
        pass_count += rsa_res.sign_verify_internal_ok;
        pass_count += rsa_res.sign_verify_external_ok;
        pass_count += rsa_res.encdec_internal_ok;
        pass_count += rsa_res.encdec_external_ok;
    }

    if (ecc_res.keygen_ok) {
        pass_count += ecc_res.export_import_ok;
        pass_count += ecc_res.sign_verify_internal_ok;
        pass_count += ecc_res.sign_verify_external_ok;
        pass_count += ecc_res.encdec_internal_ok;
        pass_count += ecc_res.encdec_external_ok;
    }

    (void)SDFU_UnloadProvider(prov);
    (void)SDF_CloseSession(sess);
    (void)SDF_CloseDevice(dev);

    printf("\n[SUMMARY] capability checks passed = %d\n", pass_count);
    return 0;
}
