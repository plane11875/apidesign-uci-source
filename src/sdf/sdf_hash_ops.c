#include <stdlib.h>
#include <string.h>

#include "uci/sdf.h"
#include "sdf_hash_state.h"

typedef struct sdf_hash_state_st {
    HANDLE session;
    HANDLE stream;
    int hmac;
    struct sdf_hash_state_st *next;
} SDF_HASH_STATE;

static SDF_HASH_STATE *g_hash_states = NULL;

static const CHAR *hash_name(ULONG uiAlgID)
{
    switch (uiAlgID) {
    case SGD_SM3:
        return (const CHAR *)"SM3";
    case SGD_SHA1:
        return (const CHAR *)"SHA1";
    case SGD_SHA256:
        return (const CHAR *)"SHA256";
    default:
        return NULL;
    }
}

static SDF_HASH_STATE *get_hash_state(HANDLE hSessionHandle, int create)
{
    SDF_HASH_STATE *cur;

    for (cur = g_hash_states; cur != NULL; cur = cur->next) {
        if (cur->session == hSessionHandle)
            return cur;
    }

    if (!create)
        return NULL;

    cur = (SDF_HASH_STATE *)calloc(1, sizeof(*cur));
    if (cur == NULL)
        return NULL;

    cur->session = hSessionHandle;
    cur->next = g_hash_states;
    g_hash_states = cur;
    return cur;
}

static void close_hash_stream(HANDLE hStream)
{
    BYTE out[128];
    ULONG out_len = sizeof(out);

    if (hStream == NULL)
        return;

    (void)SDFU_HashFinal(hStream, out, &out_len);
}

void sdf_hash_cleanup_session(HANDLE hSessionHandle)
{
    SDF_HASH_STATE *cur = g_hash_states;
    SDF_HASH_STATE *prev = NULL;
    SDF_HASH_STATE *next;

    while (cur != NULL) {
        next = cur->next;
        if (cur->session == hSessionHandle) {
            close_hash_stream(cur->stream);
            if (prev == NULL)
                g_hash_states = next;
            else
                prev->next = next;
            free(cur);
        } else {
            prev = cur;
        }
        cur = next;
    }
}

LONG SDF_HMACInit(HANDLE hSessionHandle, HANDLE hKeyHandle, ULONG uiAlgID)
{
    SDF_HASH_STATE *state;
    SDFU_HASH_REQUEST req;
    LONG rc;

    state = get_hash_state(hSessionHandle, 1);
    if (state == NULL)
        return SDR_NOBUFFER;

    if (state->stream != NULL) {
        close_hash_stream(state->stream);
        state->stream = NULL;
    }

    memset(&req, 0, sizeof(req));
    req.uiOperation = SDFU_HASH_OP_HMAC;
    req.pucAlgorithm = hash_name(uiAlgID);
    req.hKeyHandle = hKeyHandle;

    if (req.pucAlgorithm == NULL)
        return SDR_ALGNOTSUPPORT;

    rc = SDFU_HashInit(hSessionHandle, &req, &state->stream);
    if (rc != SDR_OK)
        return rc;

    state->hmac = 1;
    return SDR_OK;
}

LONG SDF_HMACUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength)
{
    SDF_HASH_STATE *state = get_hash_state(hSessionHandle, 0);

    if (state == NULL || state->stream == NULL || !state->hmac)
        return SDR_STEPERR;

    return SDFU_HashUpdate(state->stream, pucData, uiDataLength);
}

LONG SDF_HMACFinal(HANDLE hSessionHandle, BYTE *pucHmac, ULONG *puiHmacLength)
{
    SDF_HASH_STATE *state = get_hash_state(hSessionHandle, 0);
    LONG rc;

    if (state == NULL || state->stream == NULL || !state->hmac)
        return SDR_STEPERR;

    rc = SDFU_HashFinal(state->stream, pucHmac, puiHmacLength);
    state->stream = NULL;
    state->hmac = 0;
    return rc;
}

LONG SDF_HashInit(HANDLE hSessionHandle, ULONG uiAlgID,
                  ECCrefPublicKey *pucPublicKey, BYTE *pucID,
                  ULONG uiIDLength)
{
    SDF_HASH_STATE *state;
    SDFU_HASH_REQUEST req;
    LONG rc;

    (void)pucPublicKey;
    (void)pucID;
    (void)uiIDLength;

    state = get_hash_state(hSessionHandle, 1);
    if (state == NULL)
        return SDR_NOBUFFER;

    if (state->stream != NULL) {
        close_hash_stream(state->stream);
        state->stream = NULL;
    }

    memset(&req, 0, sizeof(req));
    req.uiOperation = SDFU_HASH_OP_DIGEST;
    req.pucAlgorithm = hash_name(uiAlgID);

    if (req.pucAlgorithm == NULL)
        return SDR_ALGNOTSUPPORT;

    rc = SDFU_HashInit(hSessionHandle, &req, &state->stream);
    if (rc != SDR_OK)
        return rc;

    state->hmac = 0;
    return SDR_OK;
}

LONG SDF_HashUpdate(HANDLE hSessionHandle, BYTE *pucData, ULONG uiDataLength)
{
    SDF_HASH_STATE *state = get_hash_state(hSessionHandle, 0);

    if (state == NULL || state->stream == NULL || state->hmac)
        return SDR_STEPERR;

    return SDFU_HashUpdate(state->stream, pucData, uiDataLength);
}

LONG SDF_HashFinal(HANDLE hSessionHandle, BYTE *pucHash, ULONG *puiHashLength)
{
    SDF_HASH_STATE *state = get_hash_state(hSessionHandle, 0);
    LONG rc;

    if (state == NULL || state->stream == NULL || state->hmac)
        return SDR_STEPERR;

    rc = SDFU_HashFinal(state->stream, pucHash, puiHashLength);
    state->stream = NULL;
    return rc;
}
