#include <stdlib.h>
#include <string.h>

#include "uci/sdf.h"
#include "sdf_sym_state.h"

typedef struct sdf_sym_state_st {
    HANDLE session;
    HANDLE stream;
    struct sdf_sym_state_st *next;
} SDF_SYM_STATE;

static SDF_SYM_STATE *g_sym_states = NULL;

static const char *sym_cipher_name(ULONG uiAlgID, int aead)
{
    if (aead)
        return "AES-128-GCM";

    switch (uiAlgID) {
    case SGD_SM4_ECB:
        return "SM4-ECB";
    case SGD_SM4_CBC:
        return "SM4-CBC";
    case SGD_SM4_CFB:
        return "SM4-CFB";
    case SGD_SM4_OFB:
        return "SM4-OFB";
    default:
        return NULL;
    }
}

static LONG resolve_sym_cipher(ULONG uiAlgID, int aead,
                               const CHAR **ppucAlgorithm,
                               const CHAR **ppucProperties)
{
    const CHAR *alg = sym_cipher_name(uiAlgID, aead);
    const CHAR *props = NULL;
    LONG rc;

    if (ppucAlgorithm == NULL || ppucProperties == NULL)
        return SDR_INARGERR;

    if (alg != NULL) {
        *ppucAlgorithm = alg;
        *ppucProperties = NULL;
        return SDR_OK;
    }

    rc = SDFR_ResolveAlgName(uiAlgID, &alg, &props);
    if (rc != SDR_OK)
        return SDR_ALGNOTSUPPORT;

    *ppucAlgorithm = alg;
    *ppucProperties = props;
    return SDR_OK;
}

static const char *mac_digest_name(ULONG uiAlgID)
{
    switch (uiAlgID) {
    case SGD_SHA1:
        return "SHA1";
    case SGD_SHA256:
        return "SHA256";
    case SGD_SM3:
    default:
        return "SM3";
    }
}

static SDF_SYM_STATE *get_sym_state(HANDLE hSessionHandle, int create)
{
    SDF_SYM_STATE *cur;

    for (cur = g_sym_states; cur != NULL; cur = cur->next) {
        if (cur->session == hSessionHandle)
            return cur;
    }

    if (!create)
        return NULL;

    cur = calloc(1, sizeof(*cur));
    if (cur == NULL)
        return NULL;

    cur->session = hSessionHandle;
    cur->next = g_sym_states;
    g_sym_states = cur;
    return cur;
}

static void close_stream(HANDLE hStream)
{
    BYTE out[128];
    BYTE tag[32];
    ULONG out_len = sizeof(out);
    ULONG tag_len = sizeof(tag);

    if (hStream == NULL)
        return;

    (void)SDFU_SymFinal(hStream, out, &out_len, tag, &tag_len);
}

void sdf_sym_cleanup_session(HANDLE hSessionHandle)
{
    SDF_SYM_STATE *cur = g_sym_states;
    SDF_SYM_STATE *prev = NULL;
    SDF_SYM_STATE *next;

    while (cur != NULL) {
        next = cur->next;
        if (cur->session == hSessionHandle) {
            close_stream(cur->stream);
            if (prev == NULL)
                g_sym_states = next;
            else
                prev->next = next;
            free(cur);
        } else {
            prev = cur;
        }
        cur = next;
    }
}

LONG SDF_Encrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                 BYTE *pucEncData, ULONG *puiEncDataLength)
{
    const CHAR *cipher = NULL;
    const CHAR *props = NULL;
    SDFU_SYM_REQUEST req;
    SDFU_SYM_RESPONSE rsp;
    LONG rc;

    rc = resolve_sym_cipher(uiAlgID, 0, &cipher, &props);
    if (rc != SDR_OK)
        return rc;
    if (pucData == NULL || pucEncData == NULL || puiEncDataLength == NULL)
        return SDR_OUTARGERR;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_SYM_OP_ENCRYPT;
    req.pucAlgorithm = cipher;
    req.pucProperties = props;
    req.hKeyHandle = hKeyHandle;
    req.pucIV = pucIV;
    req.uiIVLength = (pucIV == NULL) ? 0 : 16;
    req.pucInput = pucData;
    req.uiInputLength = uiDataLength;

    rsp.pucOutput = pucEncData;
    rsp.puiOutputLength = puiEncDataLength;

    return SDFU_ExecuteSymmetric(hSessionHandle, &req, &rsp);
}

LONG SDF_Decrypt(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucIV, BYTE *pucEncData, ULONG uiEncDataLength,
                 BYTE *pucData, ULONG *puiDataLength)
{
    const CHAR *cipher = NULL;
    const CHAR *props = NULL;
    SDFU_SYM_REQUEST req;
    SDFU_SYM_RESPONSE rsp;
    LONG rc;

    rc = resolve_sym_cipher(uiAlgID, 0, &cipher, &props);
    if (rc != SDR_OK)
        return rc;
    if (pucEncData == NULL || pucData == NULL || puiDataLength == NULL)
        return SDR_OUTARGERR;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_SYM_OP_DECRYPT;
    req.pucAlgorithm = cipher;
    req.pucProperties = props;
    req.hKeyHandle = hKeyHandle;
    req.pucIV = pucIV;
    req.uiIVLength = (pucIV == NULL) ? 0 : 16;
    req.pucInput = pucEncData;
    req.uiInputLength = uiEncDataLength;

    rsp.pucOutput = pucData;
    rsp.puiOutputLength = puiDataLength;

    return SDFU_ExecuteSymmetric(hSessionHandle, &req, &rsp);
}

LONG SDF_CalculateMAC(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                      BYTE *pucIV, BYTE *pucData, ULONG uiDataLength,
                      BYTE *pucMac, ULONG *puiMacLength)
{
    SDFU_SYM_REQUEST req;
    SDFU_SYM_RESPONSE rsp;

    (void)pucIV;

    if (pucData == NULL || pucMac == NULL || puiMacLength == NULL)
        return SDR_OUTARGERR;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = SDFU_SYM_OP_MAC;
    req.pucAlgorithm = (const CHAR *)mac_digest_name(uiAlgID);
    req.hKeyHandle = hKeyHandle;
    req.pucInput = pucData;
    req.uiInputLength = uiDataLength;

    rsp.pucOutput = pucMac;
    rsp.puiOutputLength = puiMacLength;

    return SDFU_ExecuteSymmetric(hSessionHandle, &req, &rsp);
}

LONG SDF_AuthEnc(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                 ULONG uiAadLength, BYTE *pucData, ULONG uiDataLength,
                 BYTE *pucEncData, ULONG *puiEncDataLength,
                 BYTE *pucAuthData, ULONG *puiAuthDataLength)
{
    LONG rc;
    ULONG mac_len;

    (void)uiAadLength;
    (void)pucAad;
    (void)uiStartVarLength;

    rc = SDF_Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                     pucData, uiDataLength, pucEncData, puiEncDataLength);
    if (rc != SDR_OK)
        return rc;

    mac_len = *puiAuthDataLength;
    rc = SDF_CalculateMAC(hSessionHandle, hKeyHandle, SGD_SM3, NULL,
                          pucEncData, *puiEncDataLength,
                          pucAuthData, &mac_len);
    if (rc != SDR_OK)
        return rc;

    *puiAuthDataLength = mac_len;
    return SDR_OK;
}

LONG SDF_AuthDec(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                 BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                 ULONG uiAadLength, BYTE *pucAuthData,
                 ULONG *puiAuthDataLength, BYTE *pucEncData,
                 ULONG uiEncDataLength, BYTE *pucData,
                 ULONG *puiDataLength)
{
    LONG rc;
    BYTE calc[64];
    ULONG calc_len = sizeof(calc);

    (void)uiAadLength;
    (void)pucAad;
    (void)uiStartVarLength;

    if (pucAuthData == NULL || puiAuthDataLength == NULL)
        return SDR_OUTARGERR;

    rc = SDF_CalculateMAC(hSessionHandle, hKeyHandle, SGD_SM3, NULL,
                          pucEncData, uiEncDataLength, calc, &calc_len);
    if (rc != SDR_OK)
        return rc;

    if (calc_len != *puiAuthDataLength ||
        memcmp(calc, pucAuthData, calc_len) != 0) {
        return SDR_MACERR;
    }

    return SDF_Decrypt(hSessionHandle, hKeyHandle, uiAlgID, pucStartVar,
                       pucEncData, uiEncDataLength, pucData, puiDataLength);
}

LONG SDF_EncryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength)
{
    SDF_SYM_STATE *st;
    SDFU_SYM_REQUEST req;
    const CHAR *cipher = NULL;
    const CHAR *props = NULL;
    LONG rc;

    rc = resolve_sym_cipher(uiAlgID, 0, &cipher, &props);
    if (rc != SDR_OK)
        return rc;

    st = get_sym_state(hSessionHandle, 1);
    if (st == NULL)
        return SDR_NOBUFFER;

    close_stream(st->stream);
    st->stream = NULL;

    memset(&req, 0, sizeof(req));
    req.uiOperation = SDFU_SYM_OP_ENCRYPT;
    req.pucAlgorithm = cipher;
    req.pucProperties = props;
    req.hKeyHandle = hKeyHandle;
    req.pucIV = pucIV;
    req.uiIVLength = uiIVLength;

    return SDFU_SymInit(hSessionHandle, &req, &st->stream);
}

LONG SDF_EncryptUpdate(HANDLE hSessionHandle, BYTE *pucData,
                       ULONG uiDataLength, BYTE *pucEncData,
                       ULONG *puiEncDataLength)
{
    SDF_SYM_STATE *st = get_sym_state(hSessionHandle, 0);

    if (st == NULL || st->stream == NULL)
        return SDR_STEPERR;

    return SDFU_SymUpdate(st->stream, pucData, uiDataLength,
                          pucEncData, puiEncDataLength);
}

LONG SDF_EncryptFinal(HANDLE hSessionHandle, BYTE *pucLastEncData,
                      ULONG *puiLastEncDataLength)
{
    SDF_SYM_STATE *st = get_sym_state(hSessionHandle, 0);
    LONG rc;

    if (st == NULL || st->stream == NULL)
        return SDR_STEPERR;

    rc = SDFU_SymFinal(st->stream, pucLastEncData, puiLastEncDataLength,
                       NULL, NULL);
    st->stream = NULL;
    return rc;
}

LONG SDF_DecryptInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucIV, ULONG uiIVLength)
{
    SDF_SYM_STATE *st;
    SDFU_SYM_REQUEST req;
    const CHAR *cipher = NULL;
    const CHAR *props = NULL;
    LONG rc;

    rc = resolve_sym_cipher(uiAlgID, 0, &cipher, &props);
    if (rc != SDR_OK)
        return rc;

    st = get_sym_state(hSessionHandle, 1);
    if (st == NULL)
        return SDR_NOBUFFER;

    close_stream(st->stream);
    st->stream = NULL;

    memset(&req, 0, sizeof(req));
    req.uiOperation = SDFU_SYM_OP_DECRYPT;
    req.pucAlgorithm = cipher;
    req.pucProperties = props;
    req.hKeyHandle = hKeyHandle;
    req.pucIV = pucIV;
    req.uiIVLength = uiIVLength;

    return SDFU_SymInit(hSessionHandle, &req, &st->stream);
}

LONG SDF_DecryptUpdate(HANDLE hSessionHandle, BYTE *pucEncData,
                       ULONG uiEncDataLength, BYTE *pucData,
                       ULONG *puiDataLength)
{
    SDF_SYM_STATE *st = get_sym_state(hSessionHandle, 0);

    if (st == NULL || st->stream == NULL)
        return SDR_STEPERR;

    return SDFU_SymUpdate(st->stream, pucEncData, uiEncDataLength,
                          pucData, puiDataLength);
}

LONG SDF_DecryptFinal(HANDLE hSessionHandle, BYTE *pucLastData,
                      ULONG *puiLastDataLength)
{
    SDF_SYM_STATE *st = get_sym_state(hSessionHandle, 0);
    LONG rc;

    if (st == NULL || st->stream == NULL)
        return SDR_STEPERR;

    rc = SDFU_SymFinal(st->stream, pucLastData, puiLastDataLength,
                       NULL, NULL);
    st->stream = NULL;
    return rc;
}

LONG SDF_CalculateMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle,
                          ULONG uiAlgID, BYTE *pucIV, ULONG uiIVLength)
{
    SDF_SYM_STATE *st;
    SDFU_SYM_REQUEST req;

    (void)pucIV;
    (void)uiIVLength;

    st = get_sym_state(hSessionHandle, 1);
    if (st == NULL)
        return SDR_NOBUFFER;

    close_stream(st->stream);
    st->stream = NULL;

    memset(&req, 0, sizeof(req));
    req.uiOperation = SDFU_SYM_OP_MAC;
    req.pucAlgorithm = (const CHAR *)mac_digest_name(uiAlgID);
    req.hKeyHandle = hKeyHandle;

    return SDFU_SymInit(hSessionHandle, &req, &st->stream);
}

LONG SDF_CalculateMACUpdate(HANDLE hSessionHandle, BYTE *pucData,
                            ULONG uiDataLength)
{
    SDF_SYM_STATE *st = get_sym_state(hSessionHandle, 0);

    if (st == NULL || st->stream == NULL)
        return SDR_STEPERR;

    return SDFU_SymUpdate(st->stream, pucData, uiDataLength, NULL, NULL);
}

LONG SDF_CalculateMACFinal(HANDLE hSessionHandle, BYTE *pucMac,
                           ULONG *puiMacLength)
{
    SDF_SYM_STATE *st = get_sym_state(hSessionHandle, 0);
    LONG rc;

    if (st == NULL || st->stream == NULL)
        return SDR_STEPERR;

    rc = SDFU_SymFinal(st->stream, pucMac, puiMacLength, NULL, NULL);
    st->stream = NULL;
    return rc;
}

LONG SDF_AuthEncInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                     ULONG uiAadLength, ULONG uiDataLength)
{
    (void)pucAad;
    (void)uiAadLength;
    (void)uiDataLength;
    return SDF_EncryptInit(hSessionHandle, hKeyHandle, uiAlgID,
                           pucStartVar, uiStartVarLength);
}

LONG SDF_AuthEncUpdate(HANDLE hSessionHandle, BYTE *pucData,
                       ULONG uiDataLength, BYTE *pucEncData,
                       ULONG *puiEncDataLength)
{
    return SDF_EncryptUpdate(hSessionHandle, pucData, uiDataLength,
                             pucEncData, puiEncDataLength);
}

LONG SDF_AuthEncFinal(HANDLE hSessionHandle, BYTE *pucLastEncData,
                      ULONG *puiLastEncDataLength, BYTE *pucAuthData,
                      ULONG *puiAuthDataLength)
{
    LONG rc = SDF_EncryptFinal(hSessionHandle, pucLastEncData, puiLastEncDataLength);

    if (rc != SDR_OK)
        return rc;
    if (pucAuthData == NULL || puiAuthDataLength == NULL || *puiAuthDataLength == 0)
        return SDR_OUTARGERR;

    memset(pucAuthData, 0, *puiAuthDataLength);
    return SDR_OK;
}

LONG SDF_AuthDecInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID,
                     BYTE *pucStartVar, ULONG uiStartVarLength, BYTE *pucAad,
                     ULONG uiAadLength, BYTE *pucAuthData,
                     ULONG uiAuthDataLength, ULONG uiDataLength)
{
    (void)pucAad;
    (void)uiAadLength;
    (void)pucAuthData;
    (void)uiAuthDataLength;
    (void)uiDataLength;
    return SDF_DecryptInit(hSessionHandle, hKeyHandle, uiAlgID,
                           pucStartVar, uiStartVarLength);
}

LONG SDF_AuthDecUpdate(HANDLE hSessionHandle, BYTE *pucEncData,
                       ULONG uiEncDataLength, BYTE *pucData,
                       ULONG *puiDataLength)
{
    return SDF_DecryptUpdate(hSessionHandle, pucEncData, uiEncDataLength,
                             pucData, puiDataLength);
}

LONG SDF_AuthDecFinal(HANDLE hSessionHandle, BYTE *pucLastData,
                      ULONG *puiLastDataLength)
{
    return SDF_DecryptFinal(hSessionHandle, pucLastData, puiLastDataLength);
}
