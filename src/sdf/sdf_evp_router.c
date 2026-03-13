#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "uci/sdf.h"

typedef struct sdf_alg_route_entry_st {
    ULONG uiAlgID;
    CHAR *pucAlgorithm;
    CHAR *pucProperties;
    struct sdf_alg_route_entry_st *next;
} SDF_ALG_ROUTE_ENTRY;

typedef struct {
    ULONG uiAlgID;
    const CHAR *pucAlgorithm;
    const CHAR *pucProperties;
} SDF_ALG_ROUTE_DEFAULT;

static SDF_ALG_ROUTE_ENTRY *g_alg_routes = NULL;
static int g_patch_checked = 0;

static const SDF_ALG_ROUTE_DEFAULT g_default_routes[] = {
    {SGD_SM3, (const CHAR *)"SM3", NULL},
    {SGD_SHA1, (const CHAR *)"SHA1", NULL},
    {SGD_SHA256, (const CHAR *)"SHA256", NULL},
    {SGD_SM4_ECB, (const CHAR *)"SM4-ECB", NULL},
    {SGD_SM4_CBC, (const CHAR *)"SM4-CBC", NULL},
    {SGD_SM4_CFB, (const CHAR *)"SM4-CFB", NULL},
    {SGD_SM4_OFB, (const CHAR *)"SM4-OFB", NULL},
    {SGD_RSA, (const CHAR *)"RSA", NULL},
    {SGD_SM2, (const CHAR *)"SM2", NULL},
    {SGD_SM2_1, (const CHAR *)"SM2", NULL},
    {SGD_SM2_2, (const CHAR *)"SM2", NULL},
    {SGD_SM2_3, (const CHAR *)"SM2", NULL},
    {SGD_MLKEM512, (const CHAR *)"mlkem512", NULL},
    {SGD_MLKEM768, (const CHAR *)"mlkem768", NULL},
    {SGD_MLKEM1024, (const CHAR *)"mlkem1024", NULL},
    {SGD_MLDSA44, (const CHAR *)"mldsa44", NULL},
    {SGD_MLDSA65, (const CHAR *)"mldsa65", NULL},
    {SGD_MLDSA87, (const CHAR *)"mldsa87", NULL},
    {0, NULL, NULL}
};

static CHAR *route_strdup(const CHAR *in)
{
    size_t len;
    CHAR *out;

    if (in == NULL)
        return NULL;

    len = strlen((const char *)in);
    out = (CHAR *)malloc(len + 1);
    if (out == NULL)
        return NULL;

    memcpy(out, in, len);
    out[len] = '\0';
    return out;
}

static CHAR *trim_left(CHAR *s)
{
    while (s != NULL && *s != '\0' && isspace((unsigned char)*s))
        s++;
    return s;
}

static void trim_right(CHAR *s)
{
    size_t n;

    if (s == NULL)
        return;

    n = strlen((const char *)s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) {
        s[n - 1] = '\0';
        n--;
    }
}

static void ensure_auto_patch_loaded(void)
{
    const CHAR *patch_file;

    if (g_patch_checked)
        return;
    g_patch_checked = 1;

    patch_file = (const CHAR *)getenv("SDFR_PATCH_FILE");
    if (patch_file != NULL && patch_file[0] != '\0')
        (void)SDFR_LoadPatchFile(patch_file);
}

static int resolve_alg_route(ULONG uiAlgID,
                             const CHAR **ppucAlgorithm,
                             const CHAR **ppucProperties)
{
    SDF_ALG_ROUTE_ENTRY *cur;
    size_t i;

    if (ppucAlgorithm == NULL || ppucProperties == NULL)
        return 0;

    ensure_auto_patch_loaded();

    *ppucAlgorithm = NULL;
    *ppucProperties = NULL;

    if (uiAlgID == 0)
        return 1;

    for (cur = g_alg_routes; cur != NULL; cur = cur->next) {
        if (cur->uiAlgID == uiAlgID) {
            *ppucAlgorithm = cur->pucAlgorithm;
            *ppucProperties = cur->pucProperties;
            return 1;
        }
    }

    for (i = 0; g_default_routes[i].uiAlgID != 0; i++) {
        if (g_default_routes[i].uiAlgID == uiAlgID) {
            *ppucAlgorithm = g_default_routes[i].pucAlgorithm;
            *ppucProperties = g_default_routes[i].pucProperties;
            return 1;
        }
    }

    return 0;
}

LONG SDFR_RegisterAlgName(ULONG uiAlgID, const CHAR *pucAlgorithm,
                          const CHAR *pucProperties)
{
    SDF_ALG_ROUTE_ENTRY *cur;
    SDF_ALG_ROUTE_ENTRY *ent;
    CHAR *alg_copy;
    CHAR *prop_copy;

    if (uiAlgID == 0 || pucAlgorithm == NULL || pucAlgorithm[0] == '\0')
        return SDR_INARGERR;

    alg_copy = route_strdup(pucAlgorithm);
    if (alg_copy == NULL)
        return SDR_NOBUFFER;

    prop_copy = route_strdup(pucProperties);

    for (cur = g_alg_routes; cur != NULL; cur = cur->next) {
        if (cur->uiAlgID == uiAlgID) {
            free(cur->pucAlgorithm);
            free(cur->pucProperties);
            cur->pucAlgorithm = alg_copy;
            cur->pucProperties = prop_copy;
            return SDR_OK;
        }
    }

    ent = (SDF_ALG_ROUTE_ENTRY *)calloc(1, sizeof(*ent));
    if (ent == NULL) {
        free(alg_copy);
        free(prop_copy);
        return SDR_NOBUFFER;
    }

    ent->uiAlgID = uiAlgID;
    ent->pucAlgorithm = alg_copy;
    ent->pucProperties = prop_copy;
    ent->next = g_alg_routes;
    g_alg_routes = ent;

    return SDR_OK;
}

LONG SDFR_UnregisterAlgName(ULONG uiAlgID)
{
    SDF_ALG_ROUTE_ENTRY *cur = g_alg_routes;
    SDF_ALG_ROUTE_ENTRY *prev = NULL;

    while (cur != NULL) {
        if (cur->uiAlgID == uiAlgID) {
            if (prev == NULL)
                g_alg_routes = cur->next;
            else
                prev->next = cur->next;

            free(cur->pucAlgorithm);
            free(cur->pucProperties);
            free(cur);
            return SDR_OK;
        }
        prev = cur;
        cur = cur->next;
    }

    return SDR_KEYNOTEXIST;
}

LONG SDFR_LoadPatchFile(const CHAR *pucPatchFile)
{
    FILE *fp;
    CHAR line[1024];
    LONG rc = SDR_OK;

    if (pucPatchFile == NULL || pucPatchFile[0] == '\0')
        return SDR_INARGERR;

    fp = fopen((const char *)pucPatchFile, "r");
    if (fp == NULL)
        return SDR_FILENOEXIST;

    while (fgets((char *)line, sizeof(line), fp) != NULL) {
        CHAR *p = trim_left(line);
        CHAR *alg;
        CHAR *prop;
        CHAR *endptr;
        unsigned long algid;

        trim_right(p);
        if (*p == '\0' || *p == '#')
            continue;

        alg = strpbrk((char *)p, " \t");
        if (alg == NULL) {
            rc = SDR_INARGERR;
            break;
        }
        *alg++ = '\0';
        alg = trim_left(alg);
        if (*alg == '\0') {
            rc = SDR_INARGERR;
            break;
        }

        prop = strpbrk((char *)alg, " \t");
        if (prop != NULL) {
            *prop++ = '\0';
            prop = trim_left(prop);
            trim_right(prop);
            if (*prop == '\0')
                prop = NULL;
        }

        algid = strtoul((const char *)p, (char **)&endptr, 0);
        if (endptr == p || *trim_left(endptr) != '\0') {
            rc = SDR_INARGERR;
            break;
        }
        if (algid > 0xFFFFFFFFul) {
            rc = SDR_INARGERR;
            break;
        }

        rc = SDFR_RegisterAlgName((ULONG)algid, alg, prop);
        if (rc != SDR_OK)
            break;
    }

    fclose(fp);
    g_patch_checked = 1;
    return rc;
}

LONG SDFR_ResolveAlgName(ULONG uiAlgID, const CHAR **ppucAlgorithm,
                         const CHAR **ppucProperties)
{
    const CHAR *alg = NULL;
    const CHAR *props = NULL;

    if (ppucAlgorithm == NULL || ppucProperties == NULL)
        return SDR_INARGERR;

    if (!resolve_alg_route(uiAlgID, &alg, &props) || alg == NULL)
        return SDR_KEYNOTEXIST;

    *ppucAlgorithm = alg;
    *ppucProperties = props;
    return SDR_OK;
}

static LONG route_hash(HANDLE hSessionHandle,
                       const SDFR_REQUEST *pstRequest,
                       SDFR_RESPONSE *pstResponse)
{
    SDFU_HASH_REQUEST req;
    SDFU_HASH_RESPONSE rsp;
    const CHAR *alg = NULL;
    const CHAR *route_props = NULL;

    if (pstRequest->pucAlgorithm != NULL) {
        alg = pstRequest->pucAlgorithm;
    } else if (!resolve_alg_route(pstRequest->uiAlgID, &alg, &route_props) || alg == NULL) {
        return SDR_ALGNOTSUPPORT;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    req.uiOperation = (pstRequest->uiOperation == SDFR_OP_HMAC)
                        ? SDFU_HASH_OP_HMAC
                        : SDFU_HASH_OP_DIGEST;
    req.pucAlgorithm = alg;
    req.pucProperties = (pstRequest->pucProperties != NULL)
                          ? pstRequest->pucProperties
                          : route_props;
    req.hKeyHandle = pstRequest->hKeyHandle;
    req.pucInput = pstRequest->pucInput;
    req.uiInputLength = pstRequest->uiInputLength;

    rsp.pucOutput = pstResponse->pucOutput;
    rsp.puiOutputLength = pstResponse->puiOutputLength;

    return SDFU_ExecuteHash(hSessionHandle, &req, &rsp);
}

static LONG route_asym(HANDLE hSessionHandle,
                       const SDFR_REQUEST *pstRequest,
                       SDFR_RESPONSE *pstResponse)
{
    SDFU_ASYM_REQUEST req;
    SDFU_ASYM_RESPONSE rsp;
    const CHAR *primary_alg = NULL;
    const CHAR *primary_props = NULL;
    const CHAR *digest_alg = NULL;
    const CHAR *digest_props = NULL;
    LONG rc;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    if (pstRequest->uiAlgID != 0)
        (void)resolve_alg_route(pstRequest->uiAlgID, &primary_alg, &primary_props);
    (void)primary_alg;

    if (pstRequest->uiDigestAlgID != 0) {
        if (!resolve_alg_route(pstRequest->uiDigestAlgID, &digest_alg, &digest_props) ||
            digest_alg == NULL) {
            return SDR_ALGNOTSUPPORT;
        }
    } else if (pstRequest->pucAlgorithm != NULL) {
        digest_alg = pstRequest->pucAlgorithm;
    }

    switch (pstRequest->uiOperation) {
    case SDFR_OP_SIGN:
        req.uiOperation = SDFU_ASYM_OP_SIGN;
        break;
    case SDFR_OP_VERIFY:
        req.uiOperation = SDFU_ASYM_OP_VERIFY;
        break;
    case SDFR_OP_PKEY_ENCRYPT:
        req.uiOperation = SDFU_ASYM_OP_PKEY_ENCRYPT;
        break;
    case SDFR_OP_PKEY_DECRYPT:
        req.uiOperation = SDFU_ASYM_OP_PKEY_DECRYPT;
        break;
    case SDFR_OP_KEM_ENCAPSULATE:
        req.uiOperation = SDFU_ASYM_OP_KEM_ENCAPSULATE;
        break;
    case SDFR_OP_KEM_DECAPSULATE:
        req.uiOperation = SDFU_ASYM_OP_KEM_DECAPSULATE;
        break;
    default:
        return SDR_NOTSUPPORT;
    }

    req.pucAlgorithm = digest_alg;
    req.pucProperties = (pstRequest->pucProperties != NULL)
                          ? pstRequest->pucProperties
                          : (primary_props != NULL ? primary_props : digest_props);
    req.hKeyHandle = pstRequest->hKeyHandle;
    req.pucInput = pstRequest->pucInput;
    req.uiInputLength = pstRequest->uiInputLength;
    req.pucExtraInput = pstRequest->pucExtraInput;
    req.uiExtraInputLength = pstRequest->uiExtraInputLength;

    rsp.pucOutput = pstResponse->pucOutput;
    rsp.puiOutputLength = pstResponse->puiOutputLength;
    rsp.pucExtraOutput = pstResponse->pucExtraOutput;
    rsp.puiExtraOutputLength = pstResponse->puiExtraOutputLength;

    rc = SDFU_ExecuteAsymmetric(hSessionHandle, &req, &rsp);
    if (rc != SDR_OK)
        return rc;

    pstResponse->lVerifyResult = rsp.lVerifyResult;
    return SDR_OK;
}

static LONG route_sym(HANDLE hSessionHandle,
                      const SDFR_REQUEST *pstRequest,
                      SDFR_RESPONSE *pstResponse)
{
    SDFU_SYM_REQUEST req;
    SDFU_SYM_RESPONSE rsp;
    const CHAR *alg = NULL;
    const CHAR *route_props = NULL;

    if (pstRequest->pucAlgorithm != NULL) {
        alg = pstRequest->pucAlgorithm;
    } else if (!resolve_alg_route(pstRequest->uiAlgID, &alg, &route_props) || alg == NULL) {
        return SDR_ALGNOTSUPPORT;
    }

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));

    switch (pstRequest->uiOperation) {
    case SDFR_OP_SYM_ENCRYPT:
        req.uiOperation = SDFU_SYM_OP_ENCRYPT;
        break;
    case SDFR_OP_SYM_DECRYPT:
        req.uiOperation = SDFU_SYM_OP_DECRYPT;
        break;
    case SDFR_OP_SYM_MAC:
        req.uiOperation = SDFU_SYM_OP_MAC;
        break;
    case SDFR_OP_SYM_AUTH_ENCRYPT:
        req.uiOperation = SDFU_SYM_OP_AUTH_ENCRYPT;
        break;
    case SDFR_OP_SYM_AUTH_DECRYPT:
        req.uiOperation = SDFU_SYM_OP_AUTH_DECRYPT;
        break;
    default:
        return SDR_NOTSUPPORT;
    }

    req.pucAlgorithm = alg;
    req.pucProperties = (pstRequest->pucProperties != NULL)
                          ? pstRequest->pucProperties
                          : route_props;
    req.hKeyHandle = pstRequest->hKeyHandle;
    req.pucIV = pstRequest->pucIV;
    req.uiIVLength = pstRequest->uiIVLength;
    req.pucAAD = pstRequest->pucAAD;
    req.uiAADLength = pstRequest->uiAADLength;
    req.pucInput = pstRequest->pucInput;
    req.uiInputLength = pstRequest->uiInputLength;
    req.pucTag = pstRequest->pucTag;
    req.uiTagLength = pstRequest->uiTagLength;

    rsp.pucOutput = pstResponse->pucOutput;
    rsp.puiOutputLength = pstResponse->puiOutputLength;
    rsp.pucTag = pstResponse->pucTag;
    rsp.puiTagLength = pstResponse->puiTagLength;

    return SDFU_ExecuteSymmetric(hSessionHandle, &req, &rsp);
}

LONG SDFR_Execute(HANDLE hSessionHandle, const SDFR_REQUEST *pstRequest,
                  SDFR_RESPONSE *pstResponse)
{
    if (hSessionHandle == NULL || pstRequest == NULL || pstResponse == NULL)
        return SDR_INARGERR;

    pstResponse->lVerifyResult = 0;

    switch (pstRequest->uiOperation) {
    case SDFR_OP_DIGEST:
    case SDFR_OP_HMAC:
        return route_hash(hSessionHandle, pstRequest, pstResponse);
    case SDFR_OP_SIGN:
    case SDFR_OP_VERIFY:
    case SDFR_OP_PKEY_ENCRYPT:
    case SDFR_OP_PKEY_DECRYPT:
    case SDFR_OP_KEM_ENCAPSULATE:
    case SDFR_OP_KEM_DECAPSULATE:
        return route_asym(hSessionHandle, pstRequest, pstResponse);
    case SDFR_OP_SYM_ENCRYPT:
    case SDFR_OP_SYM_DECRYPT:
    case SDFR_OP_SYM_MAC:
    case SDFR_OP_SYM_AUTH_ENCRYPT:
    case SDFR_OP_SYM_AUTH_DECRYPT:
        return route_sym(hSessionHandle, pstRequest, pstResponse);
    default:
        return SDR_NOTSUPPORT;
    }
}
