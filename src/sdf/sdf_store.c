#include <stdlib.h>
#include <string.h>

#include "sdf_store.h"

typedef struct sdf_internal_key_entry_st {
    HANDLE session;
    ULONG index;
    int ecc_key;
    HANDLE key_handle;
    struct sdf_internal_key_entry_st *next;
} SDF_INTERNAL_KEY_ENTRY;

typedef struct sdf_kek_entry_st {
    HANDLE session;
    ULONG index;
    BYTE key[64];
    ULONG key_len;
    struct sdf_kek_entry_st *next;
} SDF_KEK_ENTRY;

static SDF_INTERNAL_KEY_ENTRY *g_internal_keys = NULL;
static SDF_KEK_ENTRY *g_keks = NULL;

static LONG generate_internal_key(HANDLE hSessionHandle, int ecc_key,
                                  HANDLE *phKeyHandle)
{
    const CHAR *alg = ecc_key ? (const CHAR *)"SM2" : (const CHAR *)"RSA";
    return SDFU_GenerateKeyPair(hSessionHandle, alg, NULL, phKeyHandle);
}

LONG sdf_store_get_internal_key(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                int ecc_key, HANDLE *phKeyHandle)
{
    SDF_INTERNAL_KEY_ENTRY *cur;
    SDF_INTERNAL_KEY_ENTRY *ent;
    LONG rc;

    if (hSessionHandle == NULL)
        return SDR_INARGERR;
    if (uiKeyIndex == 0 || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    *phKeyHandle = NULL;

    for (cur = g_internal_keys; cur != NULL; cur = cur->next) {
        if (cur->session == hSessionHandle && cur->index == uiKeyIndex &&
            cur->ecc_key == ecc_key) {
            *phKeyHandle = cur->key_handle;
            return SDR_OK;
        }
    }

    ent = calloc(1, sizeof(*ent));
    if (ent == NULL)
        return SDR_NOBUFFER;

    rc = generate_internal_key(hSessionHandle, ecc_key, &ent->key_handle);
    if (rc != SDR_OK) {
        free(ent);
        return rc;
    }

    ent->session = hSessionHandle;
    ent->index = uiKeyIndex;
    ent->ecc_key = ecc_key;

    ent->next = g_internal_keys;
    g_internal_keys = ent;

    *phKeyHandle = ent->key_handle;
    return SDR_OK;
}

LONG sdf_store_get_or_create_kek(HANDLE hSessionHandle, ULONG uiKEKIndex,
                                 const BYTE **ppKey, ULONG *puiKeyLength)
{
    SDF_KEK_ENTRY *cur;
    SDF_KEK_ENTRY *ent;
    LONG rc;

    if (hSessionHandle == NULL)
        return SDR_INARGERR;
    if (uiKEKIndex == 0 || ppKey == NULL || puiKeyLength == NULL)
        return SDR_OUTARGERR;

    for (cur = g_keks; cur != NULL; cur = cur->next) {
        if (cur->session == hSessionHandle && cur->index == uiKEKIndex) {
            *ppKey = cur->key;
            *puiKeyLength = cur->key_len;
            return SDR_OK;
        }
    }

    ent = calloc(1, sizeof(*ent));
    if (ent == NULL)
        return SDR_NOBUFFER;

    ent->session = hSessionHandle;
    ent->index = uiKEKIndex;
    ent->key_len = 32;

    rc = SDF_GenerateRandom(hSessionHandle, ent->key_len, ent->key);
    if (rc != SDR_OK) {
        free(ent);
        return rc;
    }

    ent->next = g_keks;
    g_keks = ent;

    *ppKey = ent->key;
    *puiKeyLength = ent->key_len;
    return SDR_OK;
}

void sdf_store_cleanup_session(HANDLE hSessionHandle)
{
    SDF_INTERNAL_KEY_ENTRY *kcur;
    SDF_INTERNAL_KEY_ENTRY *kprev = NULL;
    SDF_INTERNAL_KEY_ENTRY *knext;
    SDF_KEK_ENTRY *ecur;
    SDF_KEK_ENTRY *eprev = NULL;
    SDF_KEK_ENTRY *enext;

    for (kcur = g_internal_keys; kcur != NULL; kcur = knext) {
        knext = kcur->next;
        if (kcur->session == hSessionHandle) {
            if (kprev == NULL)
                g_internal_keys = knext;
            else
                kprev->next = knext;
            SDF_DestroyKey(hSessionHandle, kcur->key_handle);
            free(kcur);
        } else {
            kprev = kcur;
        }
    }

    for (ecur = g_keks; ecur != NULL; ecur = enext) {
        enext = ecur->next;
        if (ecur->session == hSessionHandle) {
            if (eprev == NULL)
                g_keks = enext;
            else
                eprev->next = enext;
            memset(ecur->key, 0, sizeof(ecur->key));
            free(ecur);
        } else {
            eprev = ecur;
        }
    }
}
