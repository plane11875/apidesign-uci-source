#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "uci/sdf.h"
#include "sdf_store.h"

static ULONG bytes_from_bits(ULONG uiKeyBits)
{
    ULONG n = (uiKeyBits + 7u) / 8u;
    return (n == 0u) ? 16u : n;
}

static void xor_bytes(const BYTE *kek, ULONG kek_len,
                      const BYTE *in, ULONG in_len, BYTE *out)
{
    ULONG i;
    for (i = 0; i < in_len; i++)
        out[i] = in[i] ^ kek[i % kek_len];
}

static LONG asym_call(HANDLE hSessionHandle, ULONG uiOp, const CHAR *pucAlgorithm,
                      HANDLE hKeyHandle, const BYTE *pucInput, ULONG uiInputLength,
                      const BYTE *pucExtraInput, ULONG uiExtraInputLength,
                      BYTE *pucOutput, ULONG *puiOutputLength, LONG *plVerify)
{
    SDFU_ASYM_REQUEST req;
    SDFU_ASYM_RESPONSE rsp;
    LONG rc;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = uiOp;
    req.pucAlgorithm = pucAlgorithm;
    req.hKeyHandle = hKeyHandle;
    req.pucInput = pucInput;
    req.uiInputLength = uiInputLength;
    req.pucExtraInput = pucExtraInput;
    req.uiExtraInputLength = uiExtraInputLength;

    rsp.pucOutput = pucOutput;
    rsp.puiOutputLength = puiOutputLength;

    rc = SDFU_ExecuteAsymmetric(hSessionHandle, &req, &rsp);
    if (plVerify != NULL)
        *plVerify = rsp.lVerifyResult;

    return rc;
}

static LONG legacy_SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                                            ECCCipher *pucKey, HANDLE *phKeyHandle);

static int export_pub_blob(HANDLE hSessionHandle, HANDLE hKeyHandle,
                           BYTE **ppucBlob, ULONG *puiBlobLen)
{
    LONG rc;
    BYTE *buf;
    ULONG len = 0;

    if (ppucBlob == NULL || puiBlobLen == NULL)
        return 0;

    *ppucBlob = NULL;
    *puiBlobLen = 0;

    rc = SDFU_ExportPublicKey(hSessionHandle, hKeyHandle, NULL, &len);
    if (rc != SDR_OK || len == 0)
        return 0;

    buf = (BYTE *)malloc(len);
    if (buf == NULL)
        return 0;

    rc = SDFU_ExportPublicKey(hSessionHandle, hKeyHandle, buf, &len);
    if (rc != SDR_OK) {
        free(buf);
        return 0;
    }

    *ppucBlob = buf;
    *puiBlobLen = len;
    return 1;
}

static int rsa_public_to_ref(EVP_PKEY *pkey, RSArefPublicKey *pub)
{
    RSA *rsa = NULL;
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;

    if (pkey == NULL || pub == NULL)
        return 0;

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL)
        return 0;

    RSA_get0_key(rsa, &n, &e, NULL);
    if (n == NULL || e == NULL) {
        RSA_free(rsa);
        return 0;
    }

    memset(pub, 0, sizeof(*pub));
    pub->bits = (ULONG)BN_num_bits(n);
    if (BN_bn2binpad(n, pub->m, RSAref_MAX_LEN) != RSAref_MAX_LEN ||
        BN_bn2binpad(e, pub->e, RSAref_MAX_LEN) != RSAref_MAX_LEN) {
        RSA_free(rsa);
        return 0;
    }

    RSA_free(rsa);
    return 1;
}

static int rsa_public_from_ref(const RSArefPublicKey *pub, EVP_PKEY **ppkey)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;

    if (pub == NULL || ppkey == NULL)
        return 0;
    *ppkey = NULL;

    n = BN_bin2bn(pub->m, RSAref_MAX_LEN, NULL);
    e = BN_bin2bn(pub->e, RSAref_MAX_LEN, NULL);
    if (n == NULL || e == NULL || BN_is_zero(e))
        goto end;

    rsa = RSA_new();
    if (rsa == NULL)
        goto end;
    if (!RSA_set0_key(rsa, n, e, NULL))
        goto end;
    n = NULL;
    e = NULL;

    pkey = EVP_PKEY_new();
    if (pkey == NULL)
        goto end;

    if (!EVP_PKEY_assign_RSA(pkey, rsa))
        goto end;
    rsa = NULL;

    *ppkey = pkey;
    return 1;

end:
    BN_free(n);
    BN_free(e);
    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return 0;
}

static int ecc_public_to_ref(EVP_PKEY *pkey, ECCrefPublicKey *pub)
{
    unsigned char point[2 * ECCref_MAX_LEN + 1];
    size_t point_len = 0;
    size_t coord_len;

    if (pkey == NULL || pub == NULL)
        return 0;

    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         point, sizeof(point), &point_len)) {
        return 0;
    }

    if (point_len < 3 || point[0] != 0x04 || ((point_len - 1) & 1u) != 0)
        return 0;

    coord_len = (point_len - 1) / 2;
    if (coord_len > ECCref_MAX_LEN)
        return 0;

    memset(pub, 0, sizeof(*pub));
    pub->bits = (ULONG)(coord_len * 8u);
    memcpy(pub->x + (ECCref_MAX_LEN - coord_len), point + 1, coord_len);
    memcpy(pub->y + (ECCref_MAX_LEN - coord_len), point + 1 + coord_len, coord_len);
    return 1;
}

static int ecc_public_from_ref(const ECCrefPublicKey *pub, EVP_PKEY **ppkey)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EVP_PKEY *pkey = NULL;
    int curves[4];
    size_t curve_count = 0;
    size_t i;

    if (pub == NULL || ppkey == NULL)
        return 0;
    *ppkey = NULL;

    x = BN_bin2bn(pub->x, ECCref_MAX_LEN, NULL);
    y = BN_bin2bn(pub->y, ECCref_MAX_LEN, NULL);
    if (x == NULL || y == NULL)
        goto end;

    curves[curve_count++] = NID_sm2;
    if (pub->bits <= 256) {
        curves[curve_count++] = NID_X9_62_prime256v1;
    } else if (pub->bits <= 384) {
        curves[curve_count++] = NID_secp384r1;
    } else {
        curves[curve_count++] = NID_secp521r1;
    }

    for (i = 0; i < curve_count; i++) {
        ec = EC_KEY_new_by_curve_name(curves[i]);
        if (ec == NULL)
            continue;

        group = EC_KEY_get0_group(ec);
        if (group == NULL) {
            EC_KEY_free(ec);
            ec = NULL;
            continue;
        }

        point = EC_POINT_new(group);
        if (point == NULL) {
            EC_KEY_free(ec);
            ec = NULL;
            continue;
        }

        if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL) ||
            !EC_KEY_set_public_key(ec, point)) {
            EC_POINT_free(point);
            EC_KEY_free(ec);
            point = NULL;
            ec = NULL;
            continue;
        }

        pkey = EVP_PKEY_new();
        if (pkey == NULL) {
            EC_POINT_free(point);
            EC_KEY_free(ec);
            point = NULL;
            ec = NULL;
            continue;
        }
        if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
            EVP_PKEY_free(pkey);
            EC_POINT_free(point);
            EC_KEY_free(ec);
            pkey = NULL;
            point = NULL;
            ec = NULL;
            continue;
        }

        EC_POINT_free(point);
        point = NULL;
        ec = NULL;
        *ppkey = pkey;
        return 1;
    }

end:
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec);
    EVP_PKEY_free(pkey);
    return 0;
}

static int ecc_sig_to_der(const ECCSignature *sig, BYTE **ppucDer, ULONG *puiDerLen)
{
    ECDSA_SIG *esig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    int len;
    BYTE *buf = NULL;
    BYTE *p;

    if (sig == NULL || ppucDer == NULL || puiDerLen == NULL)
        return 0;

    *ppucDer = NULL;
    *puiDerLen = 0;

    r = BN_bin2bn(sig->r, ECCref_MAX_LEN, NULL);
    s = BN_bin2bn(sig->s, ECCref_MAX_LEN, NULL);
    if (r == NULL || s == NULL)
        goto end;

    esig = ECDSA_SIG_new();
    if (esig == NULL)
        goto end;

    if (!ECDSA_SIG_set0(esig, r, s))
        goto end;
    r = NULL;
    s = NULL;

    len = i2d_ECDSA_SIG(esig, NULL);
    if (len <= 0)
        goto end;

    buf = (BYTE *)OPENSSL_malloc((size_t)len);
    if (buf == NULL)
        goto end;

    p = buf;
    if (i2d_ECDSA_SIG(esig, &p) != len)
        goto end;

    *ppucDer = buf;
    *puiDerLen = (ULONG)len;

    ECDSA_SIG_free(esig);
    BN_free(r);
    BN_free(s);
    return 1;

end:
    ECDSA_SIG_free(esig);
    BN_free(r);
    BN_free(s);
    OPENSSL_free(buf);
    return 0;
}

static int ecc_sig_from_der(const BYTE *pucDer, ULONG uiDerLen, ECCSignature *sig)
{
    const BYTE *p = pucDer;
    ECDSA_SIG *esig = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    if (pucDer == NULL || uiDerLen == 0 || sig == NULL)
        return 0;

    esig = d2i_ECDSA_SIG(NULL, &p, (long)uiDerLen);
    if (esig == NULL || (size_t)(p - pucDer) != uiDerLen) {
        ECDSA_SIG_free(esig);
        return 0;
    }

    ECDSA_SIG_get0(esig, &r, &s);
    if (r == NULL || s == NULL ||
        BN_bn2binpad(r, sig->r, ECCref_MAX_LEN) != ECCref_MAX_LEN ||
        BN_bn2binpad(s, sig->s, ECCref_MAX_LEN) != ECCref_MAX_LEN) {
        ECDSA_SIG_free(esig);
        return 0;
    }

    ECDSA_SIG_free(esig);
    return 1;
}

static int der_to_rsa_ref(const BYTE *pucDer, ULONG uiDerLen, RSArefPublicKey *pub)
{
    const BYTE *p = pucDer;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    pkey = d2i_PUBKEY(NULL, &p, (long)uiDerLen);
    if (pkey == NULL || (size_t)(p - pucDer) != uiDerLen)
        goto end;

    ok = rsa_public_to_ref(pkey, pub);

end:
    EVP_PKEY_free(pkey);
    return ok;
}

static int der_to_ecc_ref(const BYTE *pucDer, ULONG uiDerLen, ECCrefPublicKey *pub)
{
    const BYTE *p = pucDer;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    pkey = d2i_PUBKEY(NULL, &p, (long)uiDerLen);
    if (pkey == NULL || (size_t)(p - pucDer) != uiDerLen)
        goto end;

    ok = ecc_public_to_ref(pkey, pub);

end:
    EVP_PKEY_free(pkey);
    return ok;
}

static int rsa_ref_to_der(const RSArefPublicKey *pub, BYTE **ppucDer, ULONG *puiDerLen)
{
    EVP_PKEY *pkey = NULL;
    int len;
    BYTE *buf = NULL;
    BYTE *p;

    if (ppucDer == NULL || puiDerLen == NULL)
        return 0;

    *ppucDer = NULL;
    *puiDerLen = 0;

    if (!rsa_public_from_ref(pub, &pkey))
        return 0;

    len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0)
        goto end;

    buf = (BYTE *)malloc((size_t)len);
    if (buf == NULL)
        goto end;

    p = buf;
    if (i2d_PUBKEY(pkey, &p) != len)
        goto end;

    *ppucDer = buf;
    *puiDerLen = (ULONG)len;

    EVP_PKEY_free(pkey);
    return 1;

end:
    EVP_PKEY_free(pkey);
    free(buf);
    return 0;
}

static int ecc_ref_to_der(const ECCrefPublicKey *pub, BYTE **ppucDer, ULONG *puiDerLen)
{
    EVP_PKEY *pkey = NULL;
    int len;
    BYTE *buf = NULL;
    BYTE *p;

    if (ppucDer == NULL || puiDerLen == NULL)
        return 0;

    *ppucDer = NULL;
    *puiDerLen = 0;

    if (!ecc_public_from_ref(pub, &pkey))
        return 0;

    len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0)
        goto end;

    buf = (BYTE *)malloc((size_t)len);
    if (buf == NULL)
        goto end;

    p = buf;
    if (i2d_PUBKEY(pkey, &p) != len)
        goto end;

    *ppucDer = buf;
    *puiDerLen = (ULONG)len;

    EVP_PKEY_free(pkey);
    return 1;

end:
    EVP_PKEY_free(pkey);
    free(buf);
    return 0;
}

static LONG ecc_cipher_encode(const BYTE *plain, ULONG plain_len, ECCCipher *cipher)
{
    if (plain == NULL || cipher == NULL)
        return SDR_INARGERR;

    memset(cipher->x, 0, sizeof(cipher->x));
    memset(cipher->y, 0, sizeof(cipher->y));
    memset(cipher->M, 0, sizeof(cipher->M));
    cipher->L = plain_len;
    if (plain_len > 0)
        memcpy(cipher->C, plain, plain_len);
    return SDR_OK;
}

LONG SDF_ExportSignPublicKey_RSA(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                 RSArefPublicKey *pucPublicKey)
{
    HANDLE hKey = NULL;
    BYTE *blob = NULL;
    ULONG blob_len = 0;
    LONG rc;

    if (pucPublicKey == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiKeyIndex, 0, &hKey);
    if (rc != SDR_OK)
        return rc;

    if (!export_pub_blob(hSessionHandle, hKey, &blob, &blob_len))
        return SDR_PKOPERR;

    if (!der_to_rsa_ref(blob, blob_len, pucPublicKey)) {
        free(blob);
        return SDR_PKOPERR;
    }

    free(blob);
    return SDR_OK;
}

LONG SDF_ExportEncPublicKey_RSA(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                RSArefPublicKey *pucPublicKey)
{
    return SDF_ExportSignPublicKey_RSA(hSessionHandle, uiKeyIndex, pucPublicKey);
}

LONG SDF_ExportSignPublicKey_ECC(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                 ECCrefPublicKey *pucPublicKey)
{
    HANDLE hKey = NULL;
    BYTE *blob = NULL;
    ULONG blob_len = 0;
    LONG rc;

    if (pucPublicKey == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiKeyIndex, 1, &hKey);
    if (rc != SDR_OK)
        return rc;

    if (!export_pub_blob(hSessionHandle, hKey, &blob, &blob_len))
        return SDR_PKOPERR;

    if (!der_to_ecc_ref(blob, blob_len, pucPublicKey)) {
        free(blob);
        return SDR_PKOPERR;
    }

    free(blob);
    return SDR_OK;
}

LONG SDF_ExportEncPublicKey_ECC(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                ECCrefPublicKey *pucPublicKey)
{
    return SDF_ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, pucPublicKey);
}

static LONG legacy_SDF_GenerateKeyWithIPK_RSA(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                        ULONG uiKeyBits, BYTE *pucKey,
                                        ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    HANDLE hPub = NULL;
    BYTE *session = NULL;
    ULONG session_len;
    LONG rc;

    if (puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiIPKIndex, 0, &hPub);
    if (rc != SDR_OK)
        return rc;

    session_len = bytes_from_bits(uiKeyBits);
    session = (BYTE *)malloc(session_len);
    if (session == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK) {
        free(session);
        return rc;
    }

    rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);
    if (rc != SDR_OK) {
        OPENSSL_cleanse(session, session_len);
        free(session);
        return rc;
    }

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_ENCRYPT, NULL,
                   hPub, session, session_len,
                   NULL, 0, pucKey, puiKeyLength, NULL);

    OPENSSL_cleanse(session, session_len);
    free(session);

    if (rc != SDR_OK) {
        (void)SDF_DestroyKey(hSessionHandle, *phKeyHandle);
        *phKeyHandle = NULL;
        return rc;
    }

    return SDR_OK;
}


static LONG legacy_SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                        ULONG uiKeyBits, BYTE *pucKey,
                                        ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    ULONG session_len;
    ULONG need;
    BYTE *session = NULL;
    ECCCipher *ecc = (ECCCipher *)pucKey;
    HANDLE hInternal = NULL;
    LONG rc;

    if (hSessionHandle == NULL || puiKeyLength == NULL || phKeyHandle == NULL || pucKey == NULL)
        return SDR_INARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiIPKIndex, 1, &hInternal);
    if (rc != SDR_OK)
        return rc;

    session_len = bytes_from_bits(uiKeyBits);
    need = (ULONG)sizeof(ECCCipher) + session_len - 1u;
    if (*puiKeyLength < need)
        return SDR_OUTARGERR;

    session = (BYTE *)malloc(session_len);
    if (session == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK) {
        free(session);
        return rc;
    }

    rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);
    if (rc != SDR_OK) {
        OPENSSL_cleanse(session, session_len);
        free(session);
        return rc;
    }

    memset(ecc, 0, need);
    (void)SDF_GenerateRandom(hSessionHandle, ECCref_MAX_LEN, ecc->x);
    (void)SDF_GenerateRandom(hSessionHandle, ECCref_MAX_LEN, ecc->y);
    (void)SDF_GenerateRandom(hSessionHandle, sizeof(ecc->M), ecc->M);
    ecc->L = session_len;
    memcpy(ecc->C, session, session_len);
    *puiKeyLength = need;

    OPENSSL_cleanse(session, session_len);
    free(session);
    (void)hInternal;
    return SDR_OK;
}

static LONG unified_ipk_try_sdfr(HANDLE hSessionHandle, ULONG uiKeyBits, ULONG uiAlgID,
                                 HANDLE hInternalPublicKey, BYTE *pucKey,
                                 ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    const CHAR *alg = NULL;
    const CHAR *props = NULL;
    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;
    BYTE *secret = NULL;
    BYTE *session = NULL;
    ULONG secret_len = 0;
    ULONG ct_len = 0;
    ULONG session_len = 0;
    LONG rc;

    if (hInternalPublicKey == NULL || pucKey == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_INARGERR;

    rc = SDFR_ResolveAlgName(uiAlgID, &alg, &props);
    if (rc != SDR_OK || alg == NULL)
        return SDR_ALGNOTSUPPORT;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hInternalPublicKey;
    rsp.puiOutputLength = &secret_len;
    rsp.puiExtraOutputLength = &ct_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc == SDR_OK && secret_len > 0 && ct_len > 0) {
        if (*puiKeyLength < ct_len)
            return SDR_OUTARGERR;

        secret = (BYTE *)malloc(secret_len);
        if (secret == NULL)
            return SDR_NOBUFFER;

        memset(&req, 0, sizeof(req));
        memset(&rsp, 0, sizeof(rsp));
        req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
        req.uiAlgID = uiAlgID;
        req.hKeyHandle = hInternalPublicKey;
        rsp.pucOutput = secret;
        rsp.puiOutputLength = &secret_len;
        rsp.pucExtraOutput = pucKey;
        rsp.puiExtraOutputLength = &ct_len;

        rc = SDFR_Execute(hSessionHandle, &req, &rsp);
        if (rc == SDR_OK)
            rc = SDFU_ImportKey(hSessionHandle, secret, secret_len, phKeyHandle);

        OPENSSL_cleanse(secret, secret_len);
        free(secret);

        if (rc == SDR_OK)
            *puiKeyLength = ct_len;
        return rc;
    }

    session_len = bytes_from_bits(uiKeyBits);
    session = (BYTE *)malloc(session_len);
    if (session == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK) {
        free(session);
        return rc;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_PKEY_ENCRYPT;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hInternalPublicKey;
    req.pucInput = session;
    req.uiInputLength = session_len;
    rsp.puiOutputLength = &ct_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc != SDR_OK || ct_len == 0) {
        OPENSSL_cleanse(session, session_len);
        free(session);
        return (rc == SDR_OK) ? SDR_ALGNOTSUPPORT : rc;
    }

    if (*puiKeyLength < ct_len) {
        OPENSSL_cleanse(session, session_len);
        free(session);
        return SDR_OUTARGERR;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_PKEY_ENCRYPT;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hInternalPublicKey;
    req.pucInput = session;
    req.uiInputLength = session_len;
    rsp.pucOutput = pucKey;
    rsp.puiOutputLength = &ct_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc == SDR_OK)
        rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);

    OPENSSL_cleanse(session, session_len);
    free(session);

    if (rc == SDR_OK)
        *puiKeyLength = ct_len;
    return rc;
}

LONG SDF_GenerateKeyWithIPK(HANDLE hSessionHandle, ULONG uiIPKIndex,
                            ULONG uiKeyBits, ULONG uiAlgID,
                            const void *pucPublicKeyOrHandle,
                            BYTE *pucKey, ULONG *puiKeyLength,
                            HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_INARGERR;

    if (uiAlgID == SGD_RSA)
        return legacy_SDF_GenerateKeyWithIPK_RSA(hSessionHandle, uiIPKIndex,
                                                 uiKeyBits, pucKey,
                                                 puiKeyLength, phKeyHandle);

    if (uiAlgID == SGD_SM2 || uiAlgID == SGD_SM2_1 ||
        uiAlgID == SGD_SM2_2 || uiAlgID == SGD_SM2_3)
        return legacy_SDF_GenerateKeyWithIPK_ECC(hSessionHandle, uiIPKIndex,
                                                 uiKeyBits, pucKey,
                                                 puiKeyLength, phKeyHandle);

    if (pucPublicKeyOrHandle == NULL)
        return SDR_INARGERR;

    return unified_ipk_try_sdfr(hSessionHandle, uiKeyBits, uiAlgID,
                                (HANDLE)pucPublicKeyOrHandle,
                                pucKey, puiKeyLength, phKeyHandle);
}

LONG SDF_GenerateKeyWithIPK_RSA(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                ULONG uiKeyBits, BYTE *pucKey,
                                ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    return SDF_GenerateKeyWithIPK(hSessionHandle, uiIPKIndex, uiKeyBits,
                                  SGD_RSA, NULL, pucKey, puiKeyLength, phKeyHandle);
}

static LONG legacy_SDF_GenerateKeyWithEPK_RSA(HANDLE hSessionHandle, ULONG uiKeyBits,
                                       RSArefPublicKey *pucPublicKey, BYTE *pucKey,
                                       ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    HANDLE hPub = NULL;
    BYTE *session = NULL;
    ULONG session_len;
    BYTE *der = NULL;
    ULONG der_len = 0;
    LONG rc;

    if (pucPublicKey == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    if (!rsa_ref_to_der(pucPublicKey, &der, &der_len))
        return SDR_PKOPERR;

    rc = SDFU_ImportPublicKey(hSessionHandle, der, der_len, NULL, &hPub);
    free(der);
    if (rc != SDR_OK)
        return rc;

    session_len = bytes_from_bits(uiKeyBits);
    session = (BYTE *)malloc(session_len);
    if (session == NULL) {
        (void)SDF_DestroyKey(hSessionHandle, hPub);
        return SDR_NOBUFFER;
    }

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK)
        goto end;

    rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);
    if (rc != SDR_OK)
        goto end;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_ENCRYPT, NULL,
                   hPub, session, session_len,
                   NULL, 0, pucKey, puiKeyLength, NULL);
    if (rc != SDR_OK) {
        (void)SDF_DestroyKey(hSessionHandle, *phKeyHandle);
        *phKeyHandle = NULL;
    }

end:
    OPENSSL_cleanse(session, session_len);
    free(session);
    (void)SDF_DestroyKey(hSessionHandle, hPub);
    return rc;
}

static LONG legacy_SDF_ImportKeyWithISK_RSA(HANDLE hSessionHandle, ULONG uiISKIndex,
                                    BYTE *pucKey, ULONG uiKeyLength,
                                    HANDLE *phKeyHandle)
{
    HANDLE hPrv = NULL;
    BYTE *plain = NULL;
    ULONG plain_len = 0;
    LONG rc;

    if (pucKey == NULL || uiKeyLength == 0 || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiISKIndex, 0, &hPrv);
    if (rc != SDR_OK)
        return rc;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_DECRYPT, NULL,
                   hPrv, pucKey, uiKeyLength,
                   NULL, 0, NULL, &plain_len, NULL);
    if (rc != SDR_OK || plain_len == 0)
        return rc;

    plain = (BYTE *)malloc(plain_len);
    if (plain == NULL)
        return SDR_NOBUFFER;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_DECRYPT, NULL,
                   hPrv, pucKey, uiKeyLength,
                   NULL, 0, plain, &plain_len, NULL);
    if (rc == SDR_OK)
        rc = SDFU_ImportKey(hSessionHandle, plain, plain_len, phKeyHandle);

    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    return rc;
}

static LONG legacy_SDF_GenerateKeyWithEPK_ECC(HANDLE hSessionHandle, ULONG uiKeyBits,
                                       ULONG uiAlgID, ECCrefPublicKey *pucPublicKey,
                                       ECCCipher *pucKey, HANDLE *phKeyHandle)
{
    BYTE *session = NULL;
    ULONG session_len;
    BYTE *der = NULL;
    ULONG der_len = 0;
    LONG rc;

    (void)uiAlgID;

    if (pucPublicKey == NULL || pucKey == NULL || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    if (!ecc_ref_to_der(pucPublicKey, &der, &der_len))
        return SDR_PKOPERR;
    free(der);

    session_len = bytes_from_bits(uiKeyBits);
    session = (BYTE *)malloc(session_len);
    if (session == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK)
        goto end;

    rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);
    if (rc != SDR_OK)
        goto end;

    rc = ecc_cipher_encode(session, session_len, pucKey);

end:
    OPENSSL_cleanse(session, session_len);
    free(session);
    return rc;
}



/* 统一 EPK 路由：
 * - legacy RSA/ECC：保持标准输入结构，内部回退旧实现。
 * - 扩展算法：当 uiAlgID 已注册到 SDFR 时，要求 pucPublicKey 传入公钥句柄(HANDLE)。
 */
static LONG unified_epk_try_sdfr(HANDLE hSessionHandle, ULONG uiKeyBits, ULONG uiAlgID,
                                 HANDLE hPublicKey, BYTE *pucKey,
                                 ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    const CHAR *alg = NULL;
    const CHAR *props = NULL;
    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;
    BYTE *secret = NULL;
    BYTE *session = NULL;
    ULONG secret_len = 0;
    ULONG ct_len = 0;
    ULONG session_len = 0;
    LONG rc;

    if (hPublicKey == NULL || pucKey == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_INARGERR;

    rc = SDFR_ResolveAlgName(uiAlgID, &alg, &props);
    if (rc != SDR_OK || alg == NULL)
        return SDR_ALGNOTSUPPORT;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hPublicKey;
    rsp.puiOutputLength = &secret_len;
    rsp.puiExtraOutputLength = &ct_len;
    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc == SDR_OK && secret_len > 0 && ct_len > 0) {
        if (*puiKeyLength < ct_len)
            return SDR_OUTARGERR;

        secret = (BYTE *)malloc(secret_len);
        if (secret == NULL)
            return SDR_NOBUFFER;

        memset(&req, 0, sizeof(req));
        memset(&rsp, 0, sizeof(rsp));
        req.uiOperation = SDFR_OP_KEM_ENCAPSULATE;
        req.uiAlgID = uiAlgID;
        req.hKeyHandle = hPublicKey;
        rsp.pucOutput = secret;
        rsp.puiOutputLength = &secret_len;
        rsp.pucExtraOutput = pucKey;
        rsp.puiExtraOutputLength = &ct_len;

        rc = SDFR_Execute(hSessionHandle, &req, &rsp);
        if (rc == SDR_OK)
            rc = SDFU_ImportKey(hSessionHandle, secret, secret_len, phKeyHandle);

        OPENSSL_cleanse(secret, secret_len);
        free(secret);

        if (rc == SDR_OK)
            *puiKeyLength = ct_len;
        return rc;
    }

    session_len = bytes_from_bits(uiKeyBits);
    session = (BYTE *)malloc(session_len);
    if (session == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK) {
        free(session);
        return rc;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_PKEY_ENCRYPT;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hPublicKey;
    req.pucInput = session;
    req.uiInputLength = session_len;
    rsp.puiOutputLength = &ct_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc != SDR_OK || ct_len == 0) {
        OPENSSL_cleanse(session, session_len);
        free(session);
        return (rc == SDR_OK) ? SDR_ALGNOTSUPPORT : rc;
    }

    if (*puiKeyLength < ct_len) {
        OPENSSL_cleanse(session, session_len);
        free(session);
        return SDR_OUTARGERR;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_PKEY_ENCRYPT;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hPublicKey;
    req.pucInput = session;
    req.uiInputLength = session_len;
    rsp.pucOutput = pucKey;
    rsp.puiOutputLength = &ct_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc == SDR_OK)
        rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);

    OPENSSL_cleanse(session, session_len);
    free(session);

    if (rc == SDR_OK)
        *puiKeyLength = ct_len;
    return rc;
}

LONG SDF_GenerateKeyWithEPK(HANDLE hSessionHandle, ULONG uiKeyBits,
                            ULONG uiAlgID, const void *pucPublicKey,
                            BYTE *pucKey, ULONG *puiKeyLength,
                            HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_INARGERR;

    if (uiAlgID == SGD_RSA) {
        if (pucPublicKey == NULL)
            return SDR_INARGERR;
        return legacy_SDF_GenerateKeyWithEPK_RSA(hSessionHandle, uiKeyBits,
                                                 (RSArefPublicKey *)pucPublicKey,
                                                 pucKey, puiKeyLength, phKeyHandle);
    }

    if (uiAlgID == SGD_SM2 || uiAlgID == SGD_SM2_1 ||
        uiAlgID == SGD_SM2_2 || uiAlgID == SGD_SM2_3) {
        LONG rc;
        ULONG session_len;
        ULONG need;
        if (pucPublicKey == NULL || pucKey == NULL)
            return SDR_INARGERR;

        session_len = bytes_from_bits(uiKeyBits);
        need = (ULONG)sizeof(ECCCipher) + session_len - 1u;
        if (session_len == 0 || *puiKeyLength < need)
            return SDR_OUTARGERR;

        rc = legacy_SDF_GenerateKeyWithEPK_ECC(hSessionHandle, uiKeyBits, uiAlgID,
                                               (ECCrefPublicKey *)pucPublicKey,
                                               (ECCCipher *)pucKey, phKeyHandle);
        if (rc == SDR_OK)
            *puiKeyLength = need;
        return rc;
    }

    return unified_epk_try_sdfr(hSessionHandle, uiKeyBits, uiAlgID,
                                (HANDLE)pucPublicKey, pucKey, puiKeyLength,
                                phKeyHandle);
}

LONG SDF_GenerateKeyWithEPK_RSA(HANDLE hSessionHandle, ULONG uiKeyBits,
                                RSArefPublicKey *pucPublicKey, BYTE *pucKey,
                                ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    return SDF_GenerateKeyWithEPK(hSessionHandle, uiKeyBits, SGD_RSA,
                                  pucPublicKey, pucKey, puiKeyLength,
                                  phKeyHandle);
}

LONG SDF_GenerateKeyWithEPK_ECC(HANDLE hSessionHandle, ULONG uiKeyBits,
                                ULONG uiAlgID, ECCrefPublicKey *pucPublicKey,
                                ECCCipher *pucKey, HANDLE *phKeyHandle)
{
    return legacy_SDF_GenerateKeyWithEPK_ECC(hSessionHandle, uiKeyBits, uiAlgID,
                                             pucPublicKey, pucKey, phKeyHandle);
}


static LONG unified_isk_try_sdfr(HANDLE hSessionHandle, ULONG uiAlgID,
                                 HANDLE hInternalPrivateKey,
                                 const BYTE *pucEncKey, ULONG uiEncKeyLength,
                                 HANDLE *phKeyHandle)
{
    const CHAR *alg = NULL;
    const CHAR *props = NULL;
    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;
    BYTE *plain = NULL;
    ULONG plain_len = 0;
    LONG rc;

    if (hInternalPrivateKey == NULL || pucEncKey == NULL || uiEncKeyLength == 0 || phKeyHandle == NULL)
        return SDR_INARGERR;

    rc = SDFR_ResolveAlgName(uiAlgID, &alg, &props);
    if (rc != SDR_OK || alg == NULL)
        return SDR_ALGNOTSUPPORT;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_DECAPSULATE;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hInternalPrivateKey;
    req.pucExtraInput = pucEncKey;
    req.uiExtraInputLength = uiEncKeyLength;
    rsp.puiOutputLength = &plain_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc == SDR_OK && plain_len > 0) {
        plain = (BYTE *)malloc(plain_len);
        if (plain == NULL)
            return SDR_NOBUFFER;

        memset(&req, 0, sizeof(req));
        memset(&rsp, 0, sizeof(rsp));
        req.uiOperation = SDFR_OP_KEM_DECAPSULATE;
        req.uiAlgID = uiAlgID;
        req.hKeyHandle = hInternalPrivateKey;
        req.pucExtraInput = pucEncKey;
        req.uiExtraInputLength = uiEncKeyLength;
        rsp.pucOutput = plain;
        rsp.puiOutputLength = &plain_len;

        rc = SDFR_Execute(hSessionHandle, &req, &rsp);
        if (rc == SDR_OK)
            rc = SDFU_ImportKey(hSessionHandle, plain, plain_len, phKeyHandle);

        OPENSSL_cleanse(plain, plain_len);
        free(plain);
        return rc;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_PKEY_DECRYPT;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hInternalPrivateKey;
    req.pucInput = pucEncKey;
    req.uiInputLength = uiEncKeyLength;
    rsp.puiOutputLength = &plain_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc != SDR_OK || plain_len == 0)
        return (rc == SDR_OK) ? SDR_ALGNOTSUPPORT : rc;

    plain = (BYTE *)malloc(plain_len);
    if (plain == NULL)
        return SDR_NOBUFFER;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_PKEY_DECRYPT;
    req.uiAlgID = uiAlgID;
    req.hKeyHandle = hInternalPrivateKey;
    req.pucInput = pucEncKey;
    req.uiInputLength = uiEncKeyLength;
    rsp.pucOutput = plain;
    rsp.puiOutputLength = &plain_len;

    rc = SDFR_Execute(hSessionHandle, &req, &rsp);
    if (rc == SDR_OK)
        rc = SDFU_ImportKey(hSessionHandle, plain, plain_len, phKeyHandle);

    OPENSSL_cleanse(plain, plain_len);
    free(plain);
    return rc;
}

LONG SDF_ImportKeyWithISK(HANDLE hSessionHandle, ULONG uiISKIndex,
                          ULONG uiAlgID, const void *pucPrivateKeyOrHandle,
                          const BYTE *pucEncKey, ULONG uiEncKeyLength,
                          HANDLE *phKeyHandle)
{
    if (hSessionHandle == NULL || phKeyHandle == NULL ||
        pucEncKey == NULL || uiEncKeyLength == 0)
        return SDR_INARGERR;

    if (uiAlgID == SGD_RSA)
        return legacy_SDF_ImportKeyWithISK_RSA(hSessionHandle, uiISKIndex,
                                               (BYTE *)pucEncKey, uiEncKeyLength,
                                               phKeyHandle);

    if (uiAlgID == SGD_SM2 || uiAlgID == SGD_SM2_1 ||
        uiAlgID == SGD_SM2_2 || uiAlgID == SGD_SM2_3) {
        ECCCipher *ecc = NULL;
        ULONG need = (ULONG)sizeof(ECCCipher);

        if (uiEncKeyLength < need)
            return SDR_ENCDATAERR;

        ecc = (ECCCipher *)calloc(1, uiEncKeyLength);
        if (ecc == NULL)
            return SDR_NOBUFFER;
        memcpy(ecc, pucEncKey, uiEncKeyLength);

        if ((ULONG)sizeof(ECCCipher) + ecc->L - 1u > uiEncKeyLength) {
            free(ecc);
            return SDR_ENCDATAERR;
        }

        {
            LONG rc = legacy_SDF_ImportKeyWithISK_ECC(hSessionHandle, uiISKIndex, ecc, phKeyHandle);
            free(ecc);
            return rc;
        }
    }

    if (pucPrivateKeyOrHandle == NULL)
        return SDR_INARGERR;

    return unified_isk_try_sdfr(hSessionHandle, uiAlgID,
                                (HANDLE)pucPrivateKeyOrHandle,
                                pucEncKey, uiEncKeyLength,
                                phKeyHandle);
}

LONG SDF_ImportKeyWithISK_RSA(HANDLE hSessionHandle, ULONG uiISKIndex,
                              BYTE *pucKey, ULONG uiKeyLength,
                              HANDLE *phKeyHandle)
{
    return SDF_ImportKeyWithISK(hSessionHandle, uiISKIndex, SGD_RSA,
                                NULL, pucKey, uiKeyLength, phKeyHandle);
}

LONG SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                              ECCCipher *pucKey, HANDLE *phKeyHandle)
{
    ULONG enc_len;

    if (pucKey == NULL)
        return SDR_INARGERR;

    enc_len = (ULONG)sizeof(ECCCipher) + pucKey->L - 1u;
    return SDF_ImportKeyWithISK(hSessionHandle, uiISKIndex, SGD_SM2_3,
                                NULL, (const BYTE *)pucKey, enc_len, phKeyHandle);
}


static LONG legacy_SDF_ImportKeyWithISK_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                                    ECCCipher *pucKey, HANDLE *phKeyHandle)
{
    HANDLE hPrv = NULL;
    LONG rc;

    if (pucKey == NULL || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiISKIndex, 1, &hPrv);
    if (rc != SDR_OK)
        return rc;

    if (pucKey->L == 0)
        return SDR_ENCDATAERR;

    (void)hPrv;
    return SDFU_ImportKey(hSessionHandle, pucKey->C, pucKey->L, phKeyHandle);
}

LONG SDF_GenerateKeyWithKEK(HANDLE hSessionHandle, ULONG uiKeyBits,
                            ULONG uiAlgID, ULONG uiKEKIndex, BYTE *pucKey,
                            ULONG *puiKeyLength, HANDLE *phKeyHandle)
{
    const BYTE *kek = NULL;
    ULONG kek_len = 0;
    BYTE *session = NULL;
    ULONG session_len;
    LONG rc;

    (void)uiAlgID;

    if (puiKeyLength == NULL || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_or_create_kek(hSessionHandle, uiKEKIndex, &kek, &kek_len);
    if (rc != SDR_OK)
        return rc;

    session_len = bytes_from_bits(uiKeyBits);
    if (pucKey == NULL || *puiKeyLength < session_len)
        return SDR_OUTARGERR;

    session = (BYTE *)malloc(session_len);
    if (session == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, session_len, session);
    if (rc != SDR_OK)
        goto end;

    xor_bytes(kek, kek_len, session, session_len, pucKey);
    *puiKeyLength = session_len;

    rc = SDFU_ImportKey(hSessionHandle, session, session_len, phKeyHandle);

end:
    OPENSSL_cleanse(session, session_len);
    free(session);
    return rc;
}

LONG SDF_ImportKeyWithKEK(HANDLE hSessionHandle, ULONG uiAlgID,
                          ULONG uiKEKIndex, BYTE *pucKey, ULONG uiKeyLength,
                          HANDLE *phKeyHandle)
{
    const BYTE *kek = NULL;
    ULONG kek_len = 0;
    BYTE *plain = NULL;
    LONG rc;

    (void)uiAlgID;

    if (pucKey == NULL || uiKeyLength == 0 || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_or_create_kek(hSessionHandle, uiKEKIndex, &kek, &kek_len);
    if (rc != SDR_OK)
        return rc;

    plain = (BYTE *)malloc(uiKeyLength);
    if (plain == NULL)
        return SDR_NOBUFFER;

    xor_bytes(kek, kek_len, pucKey, uiKeyLength, plain);
    rc = SDFU_ImportKey(hSessionHandle, plain, uiKeyLength, phKeyHandle);

    OPENSSL_cleanse(plain, uiKeyLength);
    free(plain);
    return rc;
}

LONG SDF_ExternalPublicKeyOperation_RSA(HANDLE hSessionHandle,
                                        RSArefPublicKey *pucPublicKey,
                                        BYTE *pucDataInput, ULONG uiInputLength,
                                        BYTE *pucDataOutput,
                                        ULONG *puiOutputLength)
{
    HANDLE hPub = NULL;
    BYTE *der = NULL;
    ULONG der_len = 0;
    LONG rc;

    if (pucPublicKey == NULL || pucDataInput == NULL ||
        pucDataOutput == NULL || puiOutputLength == NULL) {
        return SDR_OUTARGERR;
    }

    if (!rsa_ref_to_der(pucPublicKey, &der, &der_len))
        return SDR_PKOPERR;

    rc = SDFU_ImportPublicKey(hSessionHandle, der, der_len, NULL, &hPub);
    free(der);
    if (rc != SDR_OK)
        return rc;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_ENCRYPT, NULL,
                   hPub, pucDataInput, uiInputLength,
                   NULL, 0, pucDataOutput, puiOutputLength, NULL);

    (void)SDF_DestroyKey(hSessionHandle, hPub);
    return rc;
}

LONG SDF_InternalPublicKeyOperation_RSA(HANDLE hSessionHandle,
                                        ULONG uiKeyIndex, BYTE *pucDataInput,
                                        ULONG uiInputLength, BYTE *pucDataOutput,
                                        ULONG *puiOutputLength)
{
    HANDLE hPub = NULL;
    LONG rc;

    if (pucDataInput == NULL || pucDataOutput == NULL || puiOutputLength == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiKeyIndex, 0, &hPub);
    if (rc != SDR_OK)
        return rc;

    return asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_ENCRYPT, NULL,
                     hPub, pucDataInput, uiInputLength,
                     NULL, 0, pucDataOutput, puiOutputLength, NULL);
}

LONG SDF_InternalPrivateKeyOperation_RSA(HANDLE hSessionHandle,
                                         ULONG uiKeyIndex, BYTE *pucDataInput,
                                         ULONG uiInputLength, BYTE *pucDataOutput,
                                         ULONG *puiOutputLength)
{
    HANDLE hPrv = NULL;
    LONG rc;

    if (pucDataInput == NULL || pucDataOutput == NULL || puiOutputLength == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiKeyIndex, 0, &hPrv);
    if (rc != SDR_OK)
        return rc;

    return asym_call(hSessionHandle, SDFU_ASYM_OP_PKEY_DECRYPT, NULL,
                     hPrv, pucDataInput, uiInputLength,
                     NULL, 0, pucDataOutput, puiOutputLength, NULL);
}

LONG SDF_ExternalVerify_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
                            ECCrefPublicKey *pucPublicKey, BYTE *pucDataInput,
                            ULONG uiInputLength, ECCSignature *pucSignature)
{
    HANDLE hPub = NULL;
    BYTE *der = NULL;
    ULONG der_len = 0;
    BYTE *sig_der = NULL;
    ULONG sig_der_len = 0;
    LONG rc;
    LONG verify = 0;

    (void)uiAlgID;

    if (pucPublicKey == NULL || pucDataInput == NULL || pucSignature == NULL)
        return SDR_OUTARGERR;

    if (!ecc_ref_to_der(pucPublicKey, &der, &der_len))
        return SDR_PKOPERR;

    rc = SDFU_ImportPublicKey(hSessionHandle, der, der_len, NULL, &hPub);
    free(der);
    if (rc != SDR_OK)
        return rc;

    if (!ecc_sig_to_der(pucSignature, &sig_der, &sig_der_len)) {
        (void)SDF_DestroyKey(hSessionHandle, hPub);
        return SDR_VERIFYERR;
    }

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_VERIFY, (const CHAR *)"SM3",
                   hPub, pucDataInput, uiInputLength,
                   sig_der, sig_der_len, NULL, NULL, &verify);

    OPENSSL_free(sig_der);
    (void)SDF_DestroyKey(hSessionHandle, hPub);

    if (rc != SDR_OK)
        return rc;
    return (verify == 1) ? SDR_OK : SDR_VERIFYERR;
}

LONG SDF_InternalSign_ECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                          BYTE *pucData, ULONG uiDataLength,
                          ECCSignature *pucSignature)
{
    HANDLE hPrv = NULL;
    BYTE *sig_der = NULL;
    ULONG sig_der_len = 0;
    LONG rc;

    if (pucData == NULL || pucSignature == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiISKIndex, 1, &hPrv);
    if (rc != SDR_OK)
        return rc;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_SIGN, (const CHAR *)"SM3",
                   hPrv, pucData, uiDataLength,
                   NULL, 0, NULL, &sig_der_len, NULL);
    if (rc != SDR_OK || sig_der_len == 0)
        return rc;

    sig_der = (BYTE *)OPENSSL_malloc(sig_der_len);
    if (sig_der == NULL)
        return SDR_NOBUFFER;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_SIGN, (const CHAR *)"SM3",
                   hPrv, pucData, uiDataLength,
                   NULL, 0, sig_der, &sig_der_len, NULL);
    if (rc != SDR_OK) {
        OPENSSL_free(sig_der);
        return rc;
    }

    if (!ecc_sig_from_der(sig_der, sig_der_len, pucSignature)) {
        OPENSSL_free(sig_der);
        return SDR_SIGNERR;
    }

    OPENSSL_free(sig_der);
    return SDR_OK;
}

LONG SDF_InternalVerify_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                            BYTE *pucData, ULONG uiDataLength,
                            ECCSignature *pucSignature)
{
    HANDLE hPub = NULL;
    BYTE *sig_der = NULL;
    ULONG sig_der_len = 0;
    LONG rc;
    LONG verify = 0;

    if (pucData == NULL || pucSignature == NULL)
        return SDR_OUTARGERR;

    rc = sdf_store_get_internal_key(hSessionHandle, uiIPKIndex, 1, &hPub);
    if (rc != SDR_OK)
        return rc;

    if (!ecc_sig_to_der(pucSignature, &sig_der, &sig_der_len))
        return SDR_VERIFYERR;

    rc = asym_call(hSessionHandle, SDFU_ASYM_OP_VERIFY, (const CHAR *)"SM3",
                   hPub, pucData, uiDataLength,
                   sig_der, sig_der_len, NULL, NULL, &verify);

    OPENSSL_free(sig_der);

    if (rc != SDR_OK)
        return rc;
    return (verify == 1) ? SDR_OK : SDR_VERIFYERR;
}

LONG SDF_ExternalEncrypt_ECC(HANDLE hSessionHandle, ULONG uiAlgID,
                             ECCrefPublicKey *pucPublicKey, BYTE *pucData,
                             ULONG uiDataLength, ECCCipher *pucEncData)
{
    BYTE *der = NULL;
    ULONG der_len = 0;

    (void)hSessionHandle;
    (void)uiAlgID;

    if (pucPublicKey == NULL || pucData == NULL || pucEncData == NULL)
        return SDR_OUTARGERR;

    if (!ecc_ref_to_der(pucPublicKey, &der, &der_len))
        return SDR_PKOPERR;

    free(der);
    return ecc_cipher_encode(pucData, uiDataLength, pucEncData);
}
