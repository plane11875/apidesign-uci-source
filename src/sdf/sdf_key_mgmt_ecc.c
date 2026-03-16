#include <stdlib.h>
#include <string.h>

#include "uci/sdf.h"
#include "sdf_store.h"

typedef struct {
    HANDLE hSessionHandle;
    ULONG uiKeyBits;
    HANDLE hTmpKey;
} SDF_ECC_AGREEMENT_HANDLE;

static ULONG key_bytes_from_bits(ULONG uiKeyBits)
{
    ULONG n = (uiKeyBits + 7u) / 8u;
    return (n == 0u) ? 16u : n;
}

static void fill_dummy_ecc_pub(HANDLE hSessionHandle, ECCrefPublicKey *pucPub)
{
    if (pucPub == NULL)
        return;

    memset(pucPub, 0, sizeof(*pucPub));
    pucPub->bits = 256;
    (void)SDF_GenerateRandom(hSessionHandle, ECCref_MAX_LEN, pucPub->x);
    (void)SDF_GenerateRandom(hSessionHandle, ECCref_MAX_LEN, pucPub->y);
}

static void fill_dummy_ecc_cipher(HANDLE hSessionHandle,
                                  ECCCipher *pucKey,
                                  const BYTE *pucSession,
                                  ULONG uiSessionLen)
{
    if (pucKey == NULL)
        return;

    memset(pucKey, 0, sizeof(ECCCipher));
    (void)SDF_GenerateRandom(hSessionHandle, ECCref_MAX_LEN, pucKey->x);
    (void)SDF_GenerateRandom(hSessionHandle, ECCref_MAX_LEN, pucKey->y);
    (void)SDF_GenerateRandom(hSessionHandle, sizeof(pucKey->M), pucKey->M);
    pucKey->L = uiSessionLen;
    if (pucSession != NULL && uiSessionLen > 0)
        memcpy(pucKey->C, pucSession, uiSessionLen);
}

LONG SDF_GenerateKeyWithIPK_ECC(HANDLE hSessionHandle, ULONG uiIPKIndex,
                                ULONG uiKeyBits, ECCCipher *pucKey,
                                HANDLE *phKeyHandle)
{
    ULONG uiSessionLen;
    ULONG out_len;

    if (hSessionHandle == NULL || phKeyHandle == NULL || pucKey == NULL)
        return SDR_INARGERR;

    uiSessionLen = key_bytes_from_bits(uiKeyBits);
    out_len = (ULONG)sizeof(ECCCipher) + uiSessionLen - 1u;

    return SDF_GenerateKeyWithIPK(hSessionHandle, uiIPKIndex, uiKeyBits,
                                  SGD_SM2_3, NULL, (BYTE *)pucKey, &out_len,
                                  phKeyHandle);
}

LONG SDF_GenerateAgreementDataWithECC(HANDLE hSessionHandle, ULONG uiISKIndex,
                                      ULONG uiKeyBits, BYTE *pucSponsorID,
                                      ULONG uiSponsorIDLength,
                                      ECCrefPublicKey *pucSponsorPublicKey,
                                      ECCrefPublicKey *pucSponsorTmpPublicKey,
                                      HANDLE *phAgreementHandle)
{
    SDF_ECC_AGREEMENT_HANDLE *pstAgreement;
    HANDLE hInternal = NULL;
    HANDLE hTmpKey = NULL;
    LONG rc;

    (void)pucSponsorID;
    (void)uiSponsorIDLength;

    if (hSessionHandle == NULL || phAgreementHandle == NULL ||
        pucSponsorPublicKey == NULL || pucSponsorTmpPublicKey == NULL) {
        return SDR_INARGERR;
    }

    rc = sdf_store_get_internal_key(hSessionHandle, uiISKIndex, 1, &hInternal);
    if (rc != SDR_OK)
        return rc;

    rc = SDFU_GenerateKeyPair(hSessionHandle, (const CHAR *)"SM2", NULL, &hTmpKey);
    if (rc != SDR_OK)
        return rc;

    pstAgreement = (SDF_ECC_AGREEMENT_HANDLE *)calloc(1, sizeof(*pstAgreement));
    if (pstAgreement == NULL) {
        (void)SDF_DestroyKey(hSessionHandle, hTmpKey);
        return SDR_NOBUFFER;
    }

    pstAgreement->hSessionHandle = hSessionHandle;
    pstAgreement->uiKeyBits = uiKeyBits;
    pstAgreement->hTmpKey = hTmpKey;

    fill_dummy_ecc_pub(hSessionHandle, pucSponsorPublicKey);
    fill_dummy_ecc_pub(hSessionHandle, pucSponsorTmpPublicKey);

    *phAgreementHandle = (HANDLE)pstAgreement;
    (void)hInternal;
    return SDR_OK;
}

LONG SDF_GenerateKeyWithECC(HANDLE hSessionHandle, BYTE *pucResponseID,
                            ULONG uiResponseIDLength,
                            ECCrefPublicKey *pucResponsePublicKey,
                            ECCrefPublicKey *pucResponseTmpPublicKey,
                            HANDLE hAgreementHandle,
                            HANDLE *phKeyHandle)
{
    SDF_ECC_AGREEMENT_HANDLE *pstAgreement;
    BYTE *pucSession = NULL;
    ULONG uiSessionLen;
    LONG rc;

    (void)pucResponseID;
    (void)uiResponseIDLength;
    (void)pucResponsePublicKey;
    (void)pucResponseTmpPublicKey;

    if (hSessionHandle == NULL || hAgreementHandle == NULL || phKeyHandle == NULL)
        return SDR_INARGERR;

    pstAgreement = (SDF_ECC_AGREEMENT_HANDLE *)hAgreementHandle;
    uiSessionLen = key_bytes_from_bits(pstAgreement->uiKeyBits);

    pucSession = (BYTE *)malloc(uiSessionLen);
    if (pucSession == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, uiSessionLen, pucSession);
    if (rc != SDR_OK) {
        free(pucSession);
        return rc;
    }

    rc = SDFU_ImportKey(hSessionHandle, pucSession, uiSessionLen, phKeyHandle);
    memset(pucSession, 0, uiSessionLen);
    free(pucSession);

    if (pstAgreement->hTmpKey != NULL)
        (void)SDF_DestroyKey(pstAgreement->hSessionHandle, pstAgreement->hTmpKey);
    free(pstAgreement);

    return rc;
}

LONG SDF_GenerateAgreementDataAndKeyWithECC(HANDLE hSessionHandle,
                                            ULONG uiISKIndex, ULONG uiKeyBits,
                                            BYTE *pucResponseID,
                                            ULONG uiResponseIDLength,
                                            BYTE *pucSponsorID,
                                            ULONG uiSponsorIDLength,
                                            ECCrefPublicKey *pucSponsorPublicKey,
                                            ECCrefPublicKey *pucSponsorTmpPublicKey,
                                            ECCrefPublicKey *pucResponsePublicKey,
                                            ECCrefPublicKey *pucResponseTmpPublicKey,
                                            HANDLE *phKeyHandle)
{
    BYTE *pucSession = NULL;
    ULONG uiSessionLen;
    HANDLE hInternal = NULL;
    LONG rc;

    (void)pucResponseID;
    (void)uiResponseIDLength;
    (void)pucSponsorID;
    (void)uiSponsorIDLength;
    (void)pucSponsorPublicKey;
    (void)pucSponsorTmpPublicKey;

    if (hSessionHandle == NULL || phKeyHandle == NULL ||
        pucResponsePublicKey == NULL || pucResponseTmpPublicKey == NULL) {
        return SDR_INARGERR;
    }

    rc = sdf_store_get_internal_key(hSessionHandle, uiISKIndex, 1, &hInternal);
    if (rc != SDR_OK)
        return rc;

    uiSessionLen = key_bytes_from_bits(uiKeyBits);
    pucSession = (BYTE *)malloc(uiSessionLen);
    if (pucSession == NULL)
        return SDR_NOBUFFER;

    rc = SDF_GenerateRandom(hSessionHandle, uiSessionLen, pucSession);
    if (rc != SDR_OK) {
        free(pucSession);
        return rc;
    }

    rc = SDFU_ImportKey(hSessionHandle, pucSession, uiSessionLen, phKeyHandle);
    memset(pucSession, 0, uiSessionLen);
    free(pucSession);

    if (rc != SDR_OK)
        return rc;

    fill_dummy_ecc_pub(hSessionHandle, pucResponsePublicKey);
    fill_dummy_ecc_pub(hSessionHandle, pucResponseTmpPublicKey);

    (void)hInternal;
    return SDR_OK;
}
