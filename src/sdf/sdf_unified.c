#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include "uci/sdf.h"
#include "uci/uci_unified.h"
#include "sdf_hash_state.h"
#include "sdf_store.h"
#include "sdf_sym_state.h"

#define SDF_INTERNAL_KEY_SLOTS 32
#define SDF_MAX_KEK_BYTES 64

typedef struct sdf_file_node_st {
    char *name;
    BYTE *data;
    size_t size;
    struct sdf_file_node_st *next;
} SDF_FILE_NODE;

typedef struct {
    UCI_LIB_CTX *libctx;
    UCI_PROVIDER *default_provider;
    SDF_FILE_NODE *files;
    UCI_PKEY *internal_rsa[SDF_INTERNAL_KEY_SLOTS];
    UCI_PKEY *internal_ecc[SDF_INTERNAL_KEY_SLOTS];
    BYTE kek[SDF_INTERNAL_KEY_SLOTS][SDF_MAX_KEK_BYTES];
    size_t kek_len[SDF_INTERNAL_KEY_SLOTS];
} SDF_DEVICE_OBJ;

typedef struct {
    SDF_DEVICE_OBJ *device;
    HANDLE active_sym_stream;
    HANDLE active_hash_stream;
    HANDLE active_hmac_stream;
} SDF_SESSION_OBJ;

typedef enum {
    SDF_KEY_KIND_ASYM = 1,
    SDF_KEY_KIND_SYM = 2
} SDF_KEY_KIND;

typedef struct {
    SDF_KEY_KIND kind;
    union {
        UCI_PKEY *pkey;
        struct {
            BYTE *bytes;
            size_t len;
        } sym;
    } u;
} SDF_KEY_OBJ;

typedef enum {
    SDF_STREAM_KIND_CIPHER = 1,
    SDF_STREAM_KIND_MAC = 2
} SDF_STREAM_KIND;

typedef struct {
    SDF_STREAM_KIND kind;
    ULONG op;
    UCI_CIPHER_CTX *cipher_ctx;
    UCI_MAC_CTX *mac_ctx;
    int is_aead;
    int custom_cipher_kind;
    BYTE *xor_key;
    size_t xor_key_len;
    size_t xor_pos;
    ULONG tag_len;
} SDF_SYM_STREAM_OBJ;

typedef enum {
    SDF_HASH_STREAM_DIGEST = 1,
    SDF_HASH_STREAM_HMAC = 2
} SDF_HASH_STREAM_KIND;

typedef struct {
    SDF_HASH_STREAM_KIND kind;
    UCI_MD_CTX *md_ctx;
    UCI_MAC_CTX *mac_ctx;
} SDF_HASH_STREAM_OBJ;

typedef struct {
    ULONG uiKeyBits;
    ULONG uiISKIndex;
} SDF_AGREEMENT_OBJ;

static LONG map_asym_error(ULONG op)
{
    switch (op) {
    case SDFU_ASYM_OP_SIGN:
        return SDR_SIGNERR;
    case SDFU_ASYM_OP_VERIFY:
        return SDR_VERIFYERR;
    case SDFU_ASYM_OP_PKEY_ENCRYPT:
        return SDR_PKOPERR;
    case SDFU_ASYM_OP_PKEY_DECRYPT:
        return SDR_SKOPERR;
    case SDFU_ASYM_OP_KEM_ENCAPSULATE:
        return SDR_PKOPERR;
    case SDFU_ASYM_OP_KEM_DECAPSULATE:
        return SDR_SKOPERR;
    default:
        return SDR_UNKNOWERR;
    }
}

static void free_files(SDF_FILE_NODE *node)
{
    SDF_FILE_NODE *next;
    while (node != NULL) {
        next = node->next;
        free(node->name);
        free(node->data);
        free(node);
        node = next;
    }
}

static SDF_FILE_NODE *find_file(SDF_DEVICE_OBJ *dev, const char *name)
{
    SDF_FILE_NODE *cur = dev->files;
    while (cur != NULL) {
        if (strcmp(cur->name, name) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static int copy_name(const CHAR *in, ULONG in_len, char **out)
{
    char *buf;

    if (in == NULL || in_len == 0 || out == NULL)
        return 0;

    buf = calloc(1, (size_t)in_len + 1);
    if (buf == NULL)
        return 0;

    memcpy(buf, in, in_len);
    buf[in_len] = '\0';
    *out = buf;
    return 1;
}

static SDF_SESSION_OBJ *get_session(HANDLE hSessionHandle)
{
    return (SDF_SESSION_OBJ *)hSessionHandle;
}

static SDF_KEY_OBJ *get_key(HANDLE hKeyHandle)
{
    return (SDF_KEY_OBJ *)hKeyHandle;
}

static int ensure_asym_key(SDF_KEY_OBJ *key)
{
    return key != NULL && key->kind == SDF_KEY_KIND_ASYM && key->u.pkey != NULL;
}

static int ensure_sym_key(SDF_KEY_OBJ *key)
{
    return key != NULL && key->kind == SDF_KEY_KIND_SYM && key->u.sym.bytes != NULL && key->u.sym.len > 0;
}

static int slot_index(ULONG uiIndex, size_t *idx)
{
    if (idx == NULL || uiIndex == 0 || uiIndex > SDF_INTERNAL_KEY_SLOTS)
        return 0;
    *idx = (size_t)(uiIndex - 1);
    return 1;
}

static LONG ensure_internal_key(SDF_SESSION_OBJ *sess, ULONG uiKeyIndex,
                                const char *algorithm, UCI_PKEY **ppkey,
                                int ecc_slot)
{
    size_t idx;
    UCI_PKEY **slots;

    if (sess == NULL || algorithm == NULL || ppkey == NULL)
        return SDR_INARGERR;
    if (!slot_index(uiKeyIndex, &idx))
        return SDR_KEYNOTEXIST;

    slots = ecc_slot ? sess->device->internal_ecc : sess->device->internal_rsa;
    if (slots[idx] == NULL &&
        !UCI_KeyGenerate(sess->device->libctx, algorithm, NULL, &slots[idx])) {
        return SDR_ALGNOTSUPPORT;
    }

    *ppkey = slots[idx];
    return SDR_OK;
}

static void free_internal_keys(SDF_DEVICE_OBJ *dev)
{
    size_t i;

    for (i = 0; i < SDF_INTERNAL_KEY_SLOTS; i++) {
        UCI_PKEY_free(dev->internal_rsa[i]);
        UCI_PKEY_free(dev->internal_ecc[i]);
        OPENSSL_cleanse(dev->kek[i], sizeof(dev->kek[i]));
        dev->internal_rsa[i] = NULL;
        dev->internal_ecc[i] = NULL;
        dev->kek_len[i] = 0;
    }
}

static LONG ensure_kek(SDF_SESSION_OBJ *sess, ULONG uiKEKIndex,
                       const BYTE **ppKey, size_t *puiKeyLen)
{
    size_t idx;

    if (sess == NULL || ppKey == NULL || puiKeyLen == NULL)
        return SDR_INARGERR;
    if (!slot_index(uiKEKIndex, &idx))
        return SDR_KEYNOTEXIST;

    if (sess->device->kek_len[idx] == 0) {
        sess->device->kek_len[idx] = 32;
        if (!RAND_bytes_ex(sess->device->libctx,
                           sess->device->kek[idx],
                           sess->device->kek_len[idx], 0)) {
            sess->device->kek_len[idx] = 0;
            return SDR_RANDERR;
        }
    }

    *ppKey = sess->device->kek[idx];
    *puiKeyLen = sess->device->kek_len[idx];
    return SDR_OK;
}

static const char *hash_name_from_algid(ULONG uiAlgID)
{
    switch (uiAlgID) {
    case SGD_SM3:
        return "SM3";
    case SGD_SHA1:
        return "SHA1";
    case SGD_SHA256:
        return "SHA256";
    default:
        return NULL;
    }
}

static const char *sym_cipher_from_algid(ULONG uiAlgID, int aead)
{
    if (aead)
        return "SM4-GCM";

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

static void xor_bytes(const BYTE *key, size_t key_len,
                      const BYTE *in, size_t in_len, BYTE *out)
{
    size_t i;

    for (i = 0; i < in_len; i++)
        out[i] = in[i] ^ key[i % key_len];
}

static LONG alloc_sym_key(const BYTE *bytes, size_t len, HANDLE *phKeyHandle)
{
    SDF_KEY_OBJ *key;

    if (bytes == NULL || len == 0 || phKeyHandle == NULL)
        return SDR_INARGERR;

    *phKeyHandle = NULL;
    key = calloc(1, sizeof(*key));
    if (key == NULL)
        return SDR_NOBUFFER;

    key->u.sym.bytes = calloc(1, len);
    if (key->u.sym.bytes == NULL) {
        free(key);
        return SDR_NOBUFFER;
    }

    memcpy(key->u.sym.bytes, bytes, len);
    key->u.sym.len = len;
    key->kind = SDF_KEY_KIND_SYM;
    *phKeyHandle = (HANDLE)key;
    return SDR_OK;
}

static int rsa_public_to_ref(UCI_PKEY *pkey, RSArefPublicKey *pub)
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

static int rsa_public_from_ref(const RSArefPublicKey *pub, UCI_PKEY **ppkey)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;
    UCI_PKEY *pkey = NULL;

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

    pkey = UCI_PKEY_new();
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
    UCI_PKEY_free(pkey);
    return 0;
}

static int ecc_public_to_ref(UCI_PKEY *pkey, ECCrefPublicKey *pub)
{
    unsigned char point[2 * ECCref_MAX_LEN + 1];
    size_t point_len = 0;
    size_t coord_len;

    if (pkey == NULL || pub == NULL)
        return 0;
    if (!UCI_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         point, sizeof(point), &point_len))
        return 0;
    if (point_len < 3 || point[0] != 0x04 || ((point_len - 1) & 1u) != 0)
        return 0;

    coord_len = (point_len - 1) / 2;
    if (coord_len > ECCref_MAX_LEN)
        return 0;

    memset(pub, 0, sizeof(*pub));
    pub->bits = (ULONG)(coord_len * 8);
    memcpy(pub->x + (ECCref_MAX_LEN - coord_len), point + 1, coord_len);
    memcpy(pub->y + (ECCref_MAX_LEN - coord_len), point + 1 + coord_len, coord_len);
    return 1;
}

static int ecc_public_from_ref(const ECCrefPublicKey *pub, UCI_PKEY **ppkey)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    EC_POINT *point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    UCI_PKEY *pkey = NULL;

    if (pub == NULL || ppkey == NULL)
        return 0;
    *ppkey = NULL;

    ec = EC_KEY_new_by_curve_name(NID_sm2);
    if (ec == NULL)
        goto end;

    group = EC_KEY_get0_group(ec);
    if (group == NULL)
        goto end;

    x = BN_bin2bn(pub->x, ECCref_MAX_LEN, NULL);
    y = BN_bin2bn(pub->y, ECCref_MAX_LEN, NULL);
    if (x == NULL || y == NULL)
        goto end;

    point = EC_POINT_new(group);
    if (point == NULL)
        goto end;
    if (!EC_POINT_set_affine_coordinates(group, point, x, y, NULL))
        goto end;
    if (!EC_KEY_set_public_key(ec, point))
        goto end;

    pkey = UCI_PKEY_new();
    if (pkey == NULL)
        goto end;
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec))
        goto end;
    ec = NULL;

    *ppkey = pkey;
    return 1;

end:
    EC_POINT_free(point);
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ec);
    UCI_PKEY_free(pkey);
    return 0;
}

static int ecc_sig_from_der(const unsigned char *der, size_t der_len,
                            ECCSignature *sig)
{
    const unsigned char *p = der;
    ECDSA_SIG *esig = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    if (der == NULL || der_len == 0 || sig == NULL)
        return 0;

    esig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (esig == NULL || (size_t)(p - der) != der_len) {
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

static int ecc_sig_to_der(const ECCSignature *sig, unsigned char **der,
                          size_t *der_len)
{
    ECDSA_SIG *esig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    int len;
    unsigned char *buf = NULL;
    unsigned char *p;

    if (sig == NULL || der == NULL || der_len == NULL)
        return 0;

    *der = NULL;
    *der_len = 0;
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
    buf = OPENSSL_malloc((size_t)len);
    if (buf == NULL)
        goto end;
    p = buf;
    if (i2d_ECDSA_SIG(esig, &p) != len)
        goto end;

    *der = buf;
    *der_len = (size_t)len;
    ECDSA_SIG_free(esig);
    BN_free(r);
    BN_free(s);
    return 1;

end:
    OPENSSL_free(buf);
    ECDSA_SIG_free(esig);
    BN_free(r);
    BN_free(s);
    return 0;
}

static LONG ecc_cipher_encode_plain(const BYTE *plain, size_t plain_len, ECCCipher *cipher)
{
    if (plain == NULL || cipher == NULL)
        return SDR_INARGERR;
    if (plain_len > UINT_MAX)
        return SDR_OUTARGERR;

    memset(cipher->x, 0, sizeof(cipher->x));
    memset(cipher->y, 0, sizeof(cipher->y));
    memset(cipher->M, 0, sizeof(cipher->M));
    cipher->L = (ULONG)plain_len;
    memcpy(cipher->C, plain, plain_len);
    return SDR_OK;
}

static LONG ecc_cipher_decode_plain(const ECCCipher *cipher, BYTE *plain, size_t *plain_len)
{
    if (cipher == NULL || plain_len == NULL)
        return SDR_INARGERR;

    if (plain == NULL) {
        *plain_len = cipher->L;
        return SDR_OK;
    }

    if (*plain_len < cipher->L)
        return SDR_OUTARGERR;

    memcpy(plain, cipher->C, cipher->L);
    *plain_len = cipher->L;
    return SDR_OK;
}

static void free_sym_stream_handle(HANDLE hSymHandle)
{
    SDF_SYM_STREAM_OBJ *st = (SDF_SYM_STREAM_OBJ *)hSymHandle;

    if (st == NULL)
        return;
    UCI_CIPHER_CTX_free(st->cipher_ctx);
    UCI_MAC_CTX_free(st->mac_ctx);
    OPENSSL_clear_free(st->xor_key, st->xor_key_len);
    free(st);
}

static void free_hash_stream_handle(HANDLE hHashHandle)
{
    SDF_HASH_STREAM_OBJ *st = (SDF_HASH_STREAM_OBJ *)hHashHandle;

    if (st == NULL)
        return;
    UCI_MD_CTX_free(st->md_ctx);
    UCI_MAC_CTX_free(st->mac_ctx);
    free(st);
}

LONG SDF_OpenDevice(HANDLE *phDeviceHandle)
{
    SDF_DEVICE_OBJ *dev;

    if (phDeviceHandle == NULL)
        return SDR_OUTARGERR;

    *phDeviceHandle = NULL;

    dev = calloc(1, sizeof(*dev));
    if (dev == NULL)
        return SDR_NOBUFFER;

    dev->libctx = OSSL_LIB_CTX_new();
    if (dev->libctx == NULL) {
        free(dev);
        return SDR_UNKNOWERR;
    }

    dev->default_provider = UCI_PROVIDER_load(dev->libctx, "default");
    if (dev->default_provider == NULL) {
        OSSL_LIB_CTX_free(dev->libctx);
        free(dev);
        return SDR_NOTSUPPORT;
    }

    *phDeviceHandle = (HANDLE)dev;
    return SDR_OK;
}

LONG SDF_CloseDevice(HANDLE hDeviceHandle)
{
    SDF_DEVICE_OBJ *dev = (SDF_DEVICE_OBJ *)hDeviceHandle;

    if (dev == NULL)
        return SDR_INARGERR;

    free_internal_keys(dev);
    free_files(dev->files);
    UCI_PROVIDER_unload(dev->default_provider);
    OSSL_LIB_CTX_free(dev->libctx);
    free(dev);
    return SDR_OK;
}

LONG SDF_OpenSession(HANDLE hDeviceHandle, HANDLE *phSessionHandle)
{
    SDF_DEVICE_OBJ *dev = (SDF_DEVICE_OBJ *)hDeviceHandle;
    SDF_SESSION_OBJ *sess;

    if (dev == NULL)
        return SDR_INARGERR;
    if (phSessionHandle == NULL)
        return SDR_OUTARGERR;

    *phSessionHandle = NULL;
    sess = calloc(1, sizeof(*sess));
    if (sess == NULL)
        return SDR_NOBUFFER;

    sess->device = dev;
    *phSessionHandle = (HANDLE)sess;
    return SDR_OK;
}

LONG SDF_CloseSession(HANDLE hSessionHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);

    if (sess == NULL)
        return SDR_INARGERR;

    if (sess->active_sym_stream != NULL) {
        free_sym_stream_handle(sess->active_sym_stream);
        sess->active_sym_stream = NULL;
    }
    if (sess->active_hash_stream != NULL) {
        free_hash_stream_handle(sess->active_hash_stream);
        sess->active_hash_stream = NULL;
    }
    if (sess->active_hmac_stream != NULL) {
        free_hash_stream_handle(sess->active_hmac_stream);
        sess->active_hmac_stream = NULL;
    }

    sdf_sym_cleanup_session(hSessionHandle);
    sdf_hash_cleanup_session(hSessionHandle);
    sdf_store_cleanup_session(hSessionHandle);

    free(sess);
    return SDR_OK;
}

LONG SDF_GetDeviceInfo(HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);

    if (sess == NULL)
        return SDR_INARGERR;
    if (pstDeviceInfo == NULL)
        return SDR_OUTARGERR;

    memset(pstDeviceInfo, 0, sizeof(*pstDeviceInfo));

    memcpy(pstDeviceInfo->IssuerName, "SDF Unified Simulator", 21);
    memcpy(pstDeviceInfo->DeviceName, "SDF-UNIFIED", 11);
    memcpy(pstDeviceInfo->DeviceSerial, "2026021800000001", 16);

    pstDeviceInfo->DeviceVersion = 0x00010000;
    pstDeviceInfo->StandardVersion = 2;
    pstDeviceInfo->AsymAlgAbility[0] = 0;
    pstDeviceInfo->AsymAlgAbility[1] = 4096;
    pstDeviceInfo->SymAlgAbility = 0;
    pstDeviceInfo->HashAlgAbility = 0;
    pstDeviceInfo->BufferSize = 1024 * 1024;

    return SDR_OK;
}

LONG SDF_GenerateRandom(HANDLE hSessionHandle, ULONG uiLength, BYTE *pucRandom)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucRandom == NULL)
        return SDR_OUTARGERR;

    if (!RAND_bytes_ex(sess->device->libctx, pucRandom, (size_t)uiLength, 0))
        return SDR_RANDERR;

    return SDR_OK;
}

LONG SDF_GetPrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex,
                                  LPSTR pucPassword, ULONG uiPwdLength)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);

    if (sess == NULL)
        return SDR_INARGERR;
    if (uiKeyIndex == 0 || pucPassword == NULL || uiPwdLength == 0)
        return SDR_PRKRERR;

    return SDR_OK;
}

LONG SDF_ReleasePrivateKeyAccessRight(HANDLE hSessionHandle, ULONG uiKeyIndex)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);

    if (sess == NULL)
        return SDR_INARGERR;
    if (uiKeyIndex == 0)
        return SDR_INARGERR;

    return SDR_OK;
}

LONG SDFU_LoadProvider(HANDLE hSessionHandle, const CHAR *pucProviderName,
                      HANDLE *phProviderHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    UCI_PROVIDER *prov;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucProviderName == NULL || phProviderHandle == NULL)
        return SDR_OUTARGERR;

    prov = UCI_PROVIDER_load(sess->device->libctx, (const char *)pucProviderName);
    if (prov == NULL)
        return SDR_NOTSUPPORT;

    *phProviderHandle = (HANDLE)prov;
    return SDR_OK;
}

LONG SDFU_UnloadProvider(HANDLE hProviderHandle)
{
    UCI_PROVIDER *prov = (UCI_PROVIDER *)hProviderHandle;

    if (prov == NULL)
        return SDR_INARGERR;

    if (!UCI_PROVIDER_unload(prov))
        return SDR_UNKNOWERR;

    return SDR_OK;
}

LONG SDFU_GenerateKeyPair(HANDLE hSessionHandle, const CHAR *pucAlgorithm,
                         const CHAR *pucProperties, HANDLE *phKeyHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucAlgorithm == NULL || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    *phKeyHandle = NULL;

    key = calloc(1, sizeof(*key));
    if (key == NULL)
        return SDR_NOBUFFER;

    key->kind = SDF_KEY_KIND_ASYM;
    if (!UCI_KeyGenerate(sess->device->libctx,
                         (const char *)pucAlgorithm,
                         (const char *)pucProperties,
                         &key->u.pkey)) {
        free(key);
        return SDR_ALGNOTSUPPORT;
    }

    *phKeyHandle = (HANDLE)key;
    return SDR_OK;
}

LONG SDFU_GenerateSessionKey(HANDLE hSessionHandle, ULONG uiKeyBits,
                            HANDLE *phKeyHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;
    size_t key_len;

    if (sess == NULL)
        return SDR_INARGERR;
    if (phKeyHandle == NULL || uiKeyBits == 0)
        return SDR_OUTARGERR;

    *phKeyHandle = NULL;

    key = calloc(1, sizeof(*key));
    if (key == NULL)
        return SDR_NOBUFFER;

    key_len = (size_t)((uiKeyBits + 7) / 8);
    key->u.sym.bytes = calloc(1, key_len);
    if (key->u.sym.bytes == NULL) {
        free(key);
        return SDR_NOBUFFER;
    }

    if (!RAND_bytes_ex(sess->device->libctx, key->u.sym.bytes, key_len, 0)) {
        free(key->u.sym.bytes);
        free(key);
        return SDR_RANDERR;
    }

    key->kind = SDF_KEY_KIND_SYM;
    key->u.sym.len = key_len;
    *phKeyHandle = (HANDLE)key;
    return SDR_OK;
}

LONG SDFU_ImportKey(HANDLE hSessionHandle, const BYTE *pucKey,
                   ULONG uiKeyLength, HANDLE *phKeyHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;

    (void)sess;

    if (get_session(hSessionHandle) == NULL)
        return SDR_INARGERR;
    if (pucKey == NULL || uiKeyLength == 0 || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    *phKeyHandle = NULL;

    key = calloc(1, sizeof(*key));
    if (key == NULL)
        return SDR_NOBUFFER;

    key->u.sym.bytes = calloc(1, (size_t)uiKeyLength);
    if (key->u.sym.bytes == NULL) {
        free(key);
        return SDR_NOBUFFER;
    }

    memcpy(key->u.sym.bytes, pucKey, uiKeyLength);
    key->u.sym.len = uiKeyLength;
    key->kind = SDF_KEY_KIND_SYM;

    *phKeyHandle = (HANDLE)key;
    return SDR_OK;
}

LONG SDFU_ExportPublicKey(HANDLE hSessionHandle, HANDLE hKeyHandle,
                         BYTE *pucPublicKey, ULONG *puiPublicKeyLength)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key = get_key(hKeyHandle);
    size_t out_len;

    if (sess == NULL)
        return SDR_INARGERR;
    if (puiPublicKeyLength == NULL)
        return SDR_OUTARGERR;
    if (!ensure_asym_key(key))
        return SDR_KEYTYPEERR;

    out_len = (size_t)(*puiPublicKeyLength);
    if (!UCI_PublicKeyExport(key->u.pkey, pucPublicKey, &out_len))
        return SDR_PKOPERR;

    if (out_len > (size_t)UINT_MAX)
        return SDR_OUTARGERR;

    *puiPublicKeyLength = (ULONG)out_len;
    return SDR_OK;
}

LONG SDFU_ImportPublicKey(HANDLE hSessionHandle, const BYTE *pucPublicKey,
                         ULONG uiPublicKeyLength, const CHAR *pucProperties,
                         HANDLE *phKeyHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucPublicKey == NULL || uiPublicKeyLength == 0 || phKeyHandle == NULL)
        return SDR_OUTARGERR;

    *phKeyHandle = NULL;

    key = calloc(1, sizeof(*key));
    if (key == NULL)
        return SDR_NOBUFFER;

    key->kind = SDF_KEY_KIND_ASYM;
    if (!UCI_PublicKeyImport(sess->device->libctx,
                             (const char *)pucProperties,
                             pucPublicKey,
                             (size_t)uiPublicKeyLength,
                             &key->u.pkey)) {
        free(key);
        return SDR_PKOPERR;
    }

    *phKeyHandle = (HANDLE)key;
    return SDR_OK;
}

LONG SDF_DestroyKey(HANDLE hSessionHandle, HANDLE hKeyHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key = get_key(hKeyHandle);

    if (sess == NULL)
        return SDR_INARGERR;
    if (key == NULL)
        return SDR_KEYERR;

    if (key->kind == SDF_KEY_KIND_ASYM) {
        UCI_PKEY_free(key->u.pkey);
    } else if (key->kind == SDF_KEY_KIND_SYM) {
        OPENSSL_clear_free(key->u.sym.bytes, key->u.sym.len);
    }

    free(key);
    return SDR_OK;
}

LONG SDFU_ExecuteAsymmetric(HANDLE hSessionHandle,
                           const SDFU_ASYM_REQUEST *pstRequest,
                           SDFU_ASYM_RESPONSE *pstResponse)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;
    UCI_UNIFIED_REQUEST req;
    size_t out_len = 0;
    size_t extra_out_len = 0;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pstRequest == NULL || pstResponse == NULL)
        return SDR_OUTARGERR;

    key = get_key(pstRequest->hKeyHandle);
    if (!ensure_asym_key(key))
        return SDR_KEYTYPEERR;

    if (pstResponse->puiOutputLength != NULL)
        out_len = *pstResponse->puiOutputLength;
    if (pstResponse->puiExtraOutputLength != NULL)
        extra_out_len = *pstResponse->puiExtraOutputLength;

    if (pstRequest->uiOperation == SDFU_ASYM_OP_PKEY_ENCRYPT ||
        pstRequest->uiOperation == SDFU_ASYM_OP_PKEY_DECRYPT) {
        UCI_PKEY_CTX *ctx = UCI_PKEY_CTX_new_from_pkey(sess->device->libctx,
                                                       key->u.pkey,
                                                       (const char *)pstRequest->pucProperties);
        if (ctx == NULL)
            return map_asym_error(pstRequest->uiOperation);

        if (pstRequest->uiOperation == SDFU_ASYM_OP_PKEY_ENCRYPT) {
            if (!UCI_PKEY_encrypt_init(ctx) ||
                !UCI_PKEY_encrypt(ctx,
                                  pstResponse->pucOutput,
                                  &out_len,
                                  pstRequest->pucInput,
                                  pstRequest->uiInputLength)) {
                UCI_PKEY_CTX_free(ctx);
                return SDR_PKOPERR;
            }
        } else {
            if (!UCI_PKEY_decrypt_init(ctx) ||
                !UCI_PKEY_decrypt(ctx,
                                  pstResponse->pucOutput,
                                  &out_len,
                                  pstRequest->pucInput,
                                  pstRequest->uiInputLength)) {
                UCI_PKEY_CTX_free(ctx);
                return SDR_SKOPERR;
            }
        }

        UCI_PKEY_CTX_free(ctx);

        if (pstResponse->puiOutputLength != NULL)
            *pstResponse->puiOutputLength = (ULONG)out_len;
        return SDR_OK;
    }

    memset(&req, 0, sizeof(req));
    req.libctx = sess->device->libctx;
    req.algorithm = (const char *)pstRequest->pucAlgorithm;
    req.properties = (const char *)pstRequest->pucProperties;
    req.key = key->u.pkey;
    req.input = pstRequest->pucInput;
    req.input_len = pstRequest->uiInputLength;
    req.extra_input = pstRequest->pucExtraInput;
    req.extra_input_len = pstRequest->uiExtraInputLength;
    req.output = pstResponse->pucOutput;
    req.output_len = (pstResponse->puiOutputLength == NULL) ? NULL : &out_len;
    req.extra_output = pstResponse->pucExtraOutput;
    req.extra_output_len = (pstResponse->puiExtraOutputLength == NULL) ? NULL : &extra_out_len;

    switch (pstRequest->uiOperation) {
    case SDFU_ASYM_OP_SIGN:
        req.operation = UCI_OPERATION_SIGN;
        break;
    case SDFU_ASYM_OP_VERIFY:
        req.operation = UCI_OPERATION_VERIFY;
        break;
    case SDFU_ASYM_OP_KEM_ENCAPSULATE:
        req.operation = UCI_OPERATION_KEM_ENCAPSULATE;
        break;
    case SDFU_ASYM_OP_KEM_DECAPSULATE:
        req.operation = UCI_OPERATION_KEM_DECAPSULATE;
        break;
    default:
        return SDR_NOTSUPPORT;
    }

    if (!UCI_Execute(&req))
        return map_asym_error(pstRequest->uiOperation);

    if (pstResponse->puiOutputLength != NULL)
        *pstResponse->puiOutputLength = (ULONG)out_len;
    if (pstResponse->puiExtraOutputLength != NULL)
        *pstResponse->puiExtraOutputLength = (ULONG)extra_out_len;

    pstResponse->lVerifyResult = req.verify_ok;
    if (pstRequest->uiOperation == SDFU_ASYM_OP_VERIFY && req.verify_ok == 0)
        return SDR_VERIFYERR;

    return SDR_OK;
}

static int is_aead_cipher(const UCI_CIPHER *cipher)
{
    return (UCI_CIPHER_get_mode(cipher) == EVP_CIPH_GCM_MODE ||
            UCI_CIPHER_get_mode(cipher) == EVP_CIPH_CCM_MODE);
}

static int is_xor_algorithm(const CHAR *pucAlgorithm)
{
    if (pucAlgorithm == NULL)
        return 0;
    return OPENSSL_strcasecmp((const char *)pucAlgorithm, "XOR") == 0 ||
           OPENSSL_strcasecmp((const char *)pucAlgorithm, "XOR-STREAM") == 0;
}

static int is_subst_algorithm(const CHAR *pucAlgorithm)
{
    if (pucAlgorithm == NULL)
        return 0;
    return OPENSSL_strcasecmp((const char *)pucAlgorithm, "SUBST") == 0 ||
           OPENSSL_strcasecmp((const char *)pucAlgorithm, "SUBST-MONO") == 0 ||
           OPENSSL_strcasecmp((const char *)pucAlgorithm, "MONO-SUBST") == 0;
}

#define SDF_CUSTOM_CIPHER_NONE  0
#define SDF_CUSTOM_CIPHER_XOR   1
#define SDF_CUSTOM_CIPHER_SUBST 2

static int custom_cipher_kind(const CHAR *pucAlgorithm)
{
    if (is_xor_algorithm(pucAlgorithm))
        return SDF_CUSTOM_CIPHER_XOR;
    if (is_subst_algorithm(pucAlgorithm))
        return SDF_CUSTOM_CIPHER_SUBST;
    return SDF_CUSTOM_CIPHER_NONE;
}

static size_t xor_offset_from_iv(const BYTE *pucIV, ULONG uiIVLength, size_t key_len)
{
    size_t i;
    size_t off = 0;

    if (pucIV == NULL || uiIVLength == 0 || key_len == 0)
        return 0;

    for (i = 0; i < uiIVLength; i++)
        off = (off + (size_t)pucIV[i]) % key_len;
    return off;
}

static void xor_stream_apply(const BYTE *key, size_t key_len, size_t *pos,
                             const BYTE *in, size_t in_len, BYTE *out)
{
    size_t i;
    size_t p = (pos == NULL) ? 0 : *pos;

    for (i = 0; i < in_len; i++)
        out[i] = in[i] ^ key[(p + i) % key_len];

    if (pos != NULL)
        *pos = (p + in_len) % key_len;
}

static void subst_build_tables(const BYTE *key, size_t key_len,
                               BYTE enc[256], BYTE dec[256])
{
    size_t i;
    uint32_t seed = 0x9E3779B9u;

    for (i = 0; i < 256; i++)
        enc[i] = (BYTE)i;

    for (i = 0; i < key_len; i++)
        seed = seed * 131u + (uint32_t)key[i] + 1u;

    for (i = 255; i > 0; i--) {
        BYTE t;
        size_t j;

        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        j = (size_t)(seed % (uint32_t)(i + 1));

        t = enc[i];
        enc[i] = enc[j];
        enc[j] = t;
    }

    for (i = 0; i < 256; i++)
        dec[enc[i]] = (BYTE)i;
}

static void subst_apply(const BYTE table[256], const BYTE *in, size_t in_len, BYTE *out)
{
    size_t i;

    for (i = 0; i < in_len; i++)
        out[i] = table[in[i]];
}

LONG SDFU_ExecuteSymmetric(HANDLE hSessionHandle,
                          const SDFU_SYM_REQUEST *pstRequest,
                          SDFU_SYM_RESPONSE *pstResponse)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;

    UCI_CIPHER *cipher = NULL;
    UCI_CIPHER_CTX *ctx = NULL;
    UCI_MAC *mac = NULL;
    UCI_MAC_CTX *mac_ctx = NULL;
    OSSL_PARAM params[2];

    int len = 0;
    int tmp = 0;
    ULONG out_len = 0;
    size_t mac_len = 0;
    size_t key_pos = 0;
    int cc_kind = SDF_CUSTOM_CIPHER_NONE;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pstRequest == NULL || pstResponse == NULL)
        return SDR_OUTARGERR;

    key = get_key(pstRequest->hKeyHandle);
    if (!ensure_sym_key(key))
        return SDR_KEYTYPEERR;

    if (pstRequest->uiOperation == SDFU_SYM_OP_MAC) {
        if (pstResponse->pucOutput == NULL || pstResponse->puiOutputLength == NULL)
            return SDR_OUTARGERR;

        mac = UCI_MAC_fetch(sess->device->libctx, "HMAC", pstRequest->pucProperties);
        if (mac == NULL)
            return SDR_ALGNOTSUPPORT;

        mac_ctx = UCI_MAC_CTX_new(mac);
        UCI_MAC_free(mac);
        if (mac_ctx == NULL)
            return SDR_NOBUFFER;

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                      (void *)(pstRequest->pucAlgorithm == NULL ? "SHA256" : pstRequest->pucAlgorithm),
                                                      0);
        params[1] = OSSL_PARAM_construct_end();

        if (!UCI_MAC_init(mac_ctx, key->u.sym.bytes, key->u.sym.len, params) ||
            !UCI_MAC_update(mac_ctx, pstRequest->pucInput, pstRequest->uiInputLength) ||
            !UCI_MAC_final(mac_ctx,
                           pstResponse->pucOutput,
                           &mac_len,
                           (size_t)(*pstResponse->puiOutputLength))) {
            UCI_MAC_CTX_free(mac_ctx);
            return SDR_MACERR;
        }

        *pstResponse->puiOutputLength = (ULONG)mac_len;
        UCI_MAC_CTX_free(mac_ctx);
        return SDR_OK;
    }

    cc_kind = custom_cipher_kind(pstRequest->pucAlgorithm);
    if (cc_kind != SDF_CUSTOM_CIPHER_NONE) {
        BYTE enc_tbl[256];
        BYTE dec_tbl[256];

        if (pstResponse->pucOutput == NULL || pstResponse->puiOutputLength == NULL)
            return SDR_OUTARGERR;
        if (pstRequest->uiInputLength > 0 && pstRequest->pucInput == NULL)
            return SDR_OUTARGERR;
        if ((size_t)(*pstResponse->puiOutputLength) < (size_t)pstRequest->uiInputLength)
            return SDR_OUTARGERR;

        if (cc_kind == SDF_CUSTOM_CIPHER_XOR) {
            key_pos = xor_offset_from_iv(pstRequest->pucIV, pstRequest->uiIVLength,
                                         key->u.sym.len);
            xor_stream_apply(key->u.sym.bytes, key->u.sym.len, &key_pos,
                             pstRequest->pucInput, pstRequest->uiInputLength,
                             pstResponse->pucOutput);
        } else {
            subst_build_tables(key->u.sym.bytes, key->u.sym.len, enc_tbl, dec_tbl);
            if (pstRequest->uiOperation == SDFU_SYM_OP_ENCRYPT ||
                pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT) {
                subst_apply(enc_tbl, pstRequest->pucInput, pstRequest->uiInputLength,
                            pstResponse->pucOutput);
            } else {
                subst_apply(dec_tbl, pstRequest->pucInput, pstRequest->uiInputLength,
                            pstResponse->pucOutput);
            }
        }
        *pstResponse->puiOutputLength = pstRequest->uiInputLength;

        if (pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT &&
            pstResponse->pucTag != NULL &&
            pstResponse->puiTagLength != NULL &&
            *pstResponse->puiTagLength > 0) {
            size_t i;
            memset(pstResponse->pucTag, 0, *pstResponse->puiTagLength);
            for (i = 0; i < pstRequest->uiInputLength; i++)
                pstResponse->pucTag[i % (*pstResponse->puiTagLength)] ^= pstResponse->pucOutput[i];
        }
        return SDR_OK;
    }

    cipher = UCI_CIPHER_fetch(sess->device->libctx,
                              (const char *)pstRequest->pucAlgorithm,
                              (const char *)pstRequest->pucProperties);
    if (cipher == NULL)
        return SDR_ALGNOTSUPPORT;

    ctx = UCI_CIPHER_CTX_new();
    if (ctx == NULL) {
        UCI_CIPHER_free(cipher);
        return SDR_NOBUFFER;
    }

    if (pstRequest->uiOperation == SDFU_SYM_OP_ENCRYPT ||
        pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT) {
        if (!UCI_EncryptInit_ex(ctx, cipher, NULL, key->u.sym.bytes, pstRequest->pucIV)) {
            UCI_CIPHER_CTX_free(ctx);
            UCI_CIPHER_free(cipher);
            return SDR_SYMOPERR;
        }
    } else {
        if (!UCI_DecryptInit_ex(ctx, cipher, NULL, key->u.sym.bytes, pstRequest->pucIV)) {
            UCI_CIPHER_CTX_free(ctx);
            UCI_CIPHER_free(cipher);
            return SDR_SYMOPERR;
        }
    }

    if (is_aead_cipher(cipher)) {
        if (pstRequest->uiIVLength > 0) {
            if (!UCI_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, pstRequest->uiIVLength, NULL)) {
                UCI_CIPHER_CTX_free(ctx);
                UCI_CIPHER_free(cipher);
                return SDR_SYMOPERR;
            }
        }

        if (pstRequest->pucAAD != NULL && pstRequest->uiAADLength > 0) {
            if (pstRequest->uiOperation == SDFU_SYM_OP_ENCRYPT ||
                pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT) {
                if (!UCI_EncryptUpdate(ctx, NULL, &tmp, pstRequest->pucAAD, pstRequest->uiAADLength)) {
                    UCI_CIPHER_CTX_free(ctx);
                    UCI_CIPHER_free(cipher);
                    return SDR_SYMOPERR;
                }
            } else {
                if (!UCI_DecryptUpdate(ctx, NULL, &tmp, pstRequest->pucAAD, pstRequest->uiAADLength)) {
                    UCI_CIPHER_CTX_free(ctx);
                    UCI_CIPHER_free(cipher);
                    return SDR_SYMOPERR;
                }
            }
        }
    }

    if (pstResponse->pucOutput == NULL || pstResponse->puiOutputLength == NULL) {
        UCI_CIPHER_CTX_free(ctx);
        UCI_CIPHER_free(cipher);
        return SDR_OUTARGERR;
    }

    if (pstRequest->uiOperation == SDFU_SYM_OP_ENCRYPT ||
        pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT) {
        if (!UCI_EncryptUpdate(ctx,
                               pstResponse->pucOutput,
                               &len,
                               pstRequest->pucInput,
                               pstRequest->uiInputLength)) {
            UCI_CIPHER_CTX_free(ctx);
            UCI_CIPHER_free(cipher);
            return SDR_SYMOPERR;
        }
        out_len = (ULONG)len;
        if (!UCI_EncryptFinal_ex(ctx, pstResponse->pucOutput + out_len, &tmp)) {
            UCI_CIPHER_CTX_free(ctx);
            UCI_CIPHER_free(cipher);
            return SDR_SYMOPERR;
        }
        out_len += (ULONG)tmp;

        if (is_aead_cipher(cipher) && pstResponse->pucTag != NULL && pstResponse->puiTagLength != NULL) {
            if (!UCI_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, *pstResponse->puiTagLength, pstResponse->pucTag)) {
                UCI_CIPHER_CTX_free(ctx);
                UCI_CIPHER_free(cipher);
                return SDR_SYMOPERR;
            }
        }
    } else {
        if (is_aead_cipher(cipher) && pstRequest->pucTag != NULL && pstRequest->uiTagLength > 0) {
            if (!UCI_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, pstRequest->uiTagLength, (void *)pstRequest->pucTag)) {
                UCI_CIPHER_CTX_free(ctx);
                UCI_CIPHER_free(cipher);
                return SDR_SYMOPERR;
            }
        }

        if (!UCI_DecryptUpdate(ctx,
                               pstResponse->pucOutput,
                               &len,
                               pstRequest->pucInput,
                               pstRequest->uiInputLength)) {
            UCI_CIPHER_CTX_free(ctx);
            UCI_CIPHER_free(cipher);
            return SDR_SYMOPERR;
        }
        out_len = (ULONG)len;

        if (!UCI_DecryptFinal_ex(ctx, pstResponse->pucOutput + out_len, &tmp)) {
            UCI_CIPHER_CTX_free(ctx);
            UCI_CIPHER_free(cipher);
            return SDR_SYMOPERR;
        }
        out_len += (ULONG)tmp;
    }

    *pstResponse->puiOutputLength = out_len;

    UCI_CIPHER_CTX_free(ctx);
    UCI_CIPHER_free(cipher);
    return SDR_OK;
}

LONG SDFU_SymInit(HANDLE hSessionHandle,
                 const SDFU_SYM_REQUEST *pstRequest,
                 HANDLE *phSymHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;
    SDF_SYM_STREAM_OBJ *st;
    UCI_CIPHER *cipher;
    UCI_MAC *mac;
    OSSL_PARAM params[2];
    int tmp = 0;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pstRequest == NULL || phSymHandle == NULL)
        return SDR_OUTARGERR;

    *phSymHandle = NULL;

    key = get_key(pstRequest->hKeyHandle);
    if (!ensure_sym_key(key))
        return SDR_KEYTYPEERR;

    st = calloc(1, sizeof(*st));
    if (st == NULL)
        return SDR_NOBUFFER;

    st->op = pstRequest->uiOperation;

    if (pstRequest->uiOperation == SDFU_SYM_OP_MAC) {
        st->kind = SDF_STREAM_KIND_MAC;
        mac = UCI_MAC_fetch(sess->device->libctx, "HMAC", pstRequest->pucProperties);
        if (mac == NULL) {
            free(st);
            return SDR_ALGNOTSUPPORT;
        }
        st->mac_ctx = UCI_MAC_CTX_new(mac);
        UCI_MAC_free(mac);
        if (st->mac_ctx == NULL) {
            free(st);
            return SDR_NOBUFFER;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                      (void *)(pstRequest->pucAlgorithm == NULL ? "SHA256" : pstRequest->pucAlgorithm),
                                                      0);
        params[1] = OSSL_PARAM_construct_end();

        if (!UCI_MAC_init(st->mac_ctx, key->u.sym.bytes, key->u.sym.len, params)) {
            UCI_MAC_CTX_free(st->mac_ctx);
            free(st);
            return SDR_MACERR;
        }

        *phSymHandle = (HANDLE)st;
        return SDR_OK;
    }

    st->kind = SDF_STREAM_KIND_CIPHER;
    st->cipher_ctx = UCI_CIPHER_CTX_new();
    if (st->cipher_ctx == NULL) {
        free(st);
        return SDR_NOBUFFER;
    }

    st->custom_cipher_kind = custom_cipher_kind(pstRequest->pucAlgorithm);
    if (st->custom_cipher_kind != SDF_CUSTOM_CIPHER_NONE) {
        UCI_CIPHER_CTX_free(st->cipher_ctx);
        st->cipher_ctx = NULL;
        st->xor_pos = 0;
        st->xor_key = OPENSSL_memdup(key->u.sym.bytes, key->u.sym.len);
        if (st->xor_key == NULL) {
            free(st);
            return SDR_NOBUFFER;
        }
        st->xor_key_len = key->u.sym.len;
        if (st->custom_cipher_kind == SDF_CUSTOM_CIPHER_XOR) {
            st->xor_pos = xor_offset_from_iv(pstRequest->pucIV, pstRequest->uiIVLength,
                                             st->xor_key_len);
        }
        *phSymHandle = (HANDLE)st;
        return SDR_OK;
    }

    cipher = UCI_CIPHER_fetch(sess->device->libctx,
                              (const char *)pstRequest->pucAlgorithm,
                              (const char *)pstRequest->pucProperties);
    if (cipher == NULL) {
        UCI_CIPHER_CTX_free(st->cipher_ctx);
        free(st);
        return SDR_ALGNOTSUPPORT;
    }

    st->is_aead = is_aead_cipher(cipher);

    if (pstRequest->uiOperation == SDFU_SYM_OP_ENCRYPT ||
        pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT) {
        if (!UCI_EncryptInit_ex(st->cipher_ctx, cipher, NULL, key->u.sym.bytes, pstRequest->pucIV)) {
            UCI_CIPHER_free(cipher);
            UCI_CIPHER_CTX_free(st->cipher_ctx);
            free(st);
            return SDR_SYMOPERR;
        }
    } else {
        if (!UCI_DecryptInit_ex(st->cipher_ctx, cipher, NULL, key->u.sym.bytes, pstRequest->pucIV)) {
            UCI_CIPHER_free(cipher);
            UCI_CIPHER_CTX_free(st->cipher_ctx);
            free(st);
            return SDR_SYMOPERR;
        }
    }

    if (st->is_aead) {
        st->tag_len = pstRequest->uiTagLength;
        if (pstRequest->uiIVLength > 0 &&
            !UCI_CIPHER_CTX_ctrl(st->cipher_ctx, EVP_CTRL_AEAD_SET_IVLEN, pstRequest->uiIVLength, NULL)) {
            UCI_CIPHER_free(cipher);
            UCI_CIPHER_CTX_free(st->cipher_ctx);
            free(st);
            return SDR_SYMOPERR;
        }

        if ((pstRequest->uiOperation == SDFU_SYM_OP_DECRYPT ||
             pstRequest->uiOperation == SDFU_SYM_OP_AUTH_DECRYPT) &&
            pstRequest->pucTag != NULL && pstRequest->uiTagLength > 0) {
            if (!UCI_CIPHER_CTX_ctrl(st->cipher_ctx,
                                     EVP_CTRL_AEAD_SET_TAG,
                                     pstRequest->uiTagLength,
                                     (void *)pstRequest->pucTag)) {
                UCI_CIPHER_free(cipher);
                UCI_CIPHER_CTX_free(st->cipher_ctx);
                free(st);
                return SDR_SYMOPERR;
            }
        }

        if (pstRequest->pucAAD != NULL && pstRequest->uiAADLength > 0) {
            if (pstRequest->uiOperation == SDFU_SYM_OP_ENCRYPT ||
                pstRequest->uiOperation == SDFU_SYM_OP_AUTH_ENCRYPT) {
                if (!UCI_EncryptUpdate(st->cipher_ctx, NULL, &tmp,
                                       pstRequest->pucAAD,
                                       pstRequest->uiAADLength)) {
                    UCI_CIPHER_free(cipher);
                    UCI_CIPHER_CTX_free(st->cipher_ctx);
                    free(st);
                    return SDR_SYMOPERR;
                }
            } else {
                if (!UCI_DecryptUpdate(st->cipher_ctx, NULL, &tmp,
                                       pstRequest->pucAAD,
                                       pstRequest->uiAADLength)) {
                    UCI_CIPHER_free(cipher);
                    UCI_CIPHER_CTX_free(st->cipher_ctx);
                    free(st);
                    return SDR_SYMOPERR;
                }
            }
        }
    }

    UCI_CIPHER_free(cipher);
    *phSymHandle = (HANDLE)st;
    return SDR_OK;
}

LONG SDFU_SymUpdate(HANDLE hSymHandle,
                   const BYTE *pucInput,
                   ULONG uiInputLength,
                   BYTE *pucOutput,
                   ULONG *puiOutputLength)
{
    SDF_SYM_STREAM_OBJ *st = (SDF_SYM_STREAM_OBJ *)hSymHandle;
    int out_len = 0;

    if (st == NULL)
        return SDR_INARGERR;

    if (st->kind == SDF_STREAM_KIND_MAC) {
        if (puiOutputLength != NULL)
            *puiOutputLength = 0;
        if (!UCI_MAC_update(st->mac_ctx, pucInput, uiInputLength))
            return SDR_MACERR;
        return SDR_OK;
    }

    if (pucOutput == NULL || puiOutputLength == NULL)
        return SDR_OUTARGERR;

    if (st->custom_cipher_kind != SDF_CUSTOM_CIPHER_NONE) {
        BYTE enc_tbl[256];
        BYTE dec_tbl[256];

        if (uiInputLength > 0 && pucInput == NULL)
            return SDR_OUTARGERR;
        if ((size_t)(*puiOutputLength) < (size_t)uiInputLength)
            return SDR_OUTARGERR;

        if (st->custom_cipher_kind == SDF_CUSTOM_CIPHER_XOR) {
            xor_stream_apply(st->xor_key, st->xor_key_len, &st->xor_pos,
                             pucInput, uiInputLength, pucOutput);
        } else {
            subst_build_tables(st->xor_key, st->xor_key_len, enc_tbl, dec_tbl);
            if (st->op == SDFU_SYM_OP_ENCRYPT || st->op == SDFU_SYM_OP_AUTH_ENCRYPT)
                subst_apply(enc_tbl, pucInput, uiInputLength, pucOutput);
            else
                subst_apply(dec_tbl, pucInput, uiInputLength, pucOutput);
        }

        *puiOutputLength = uiInputLength;
        return SDR_OK;
    }

    if (st->op == SDFU_SYM_OP_ENCRYPT || st->op == SDFU_SYM_OP_AUTH_ENCRYPT) {
        if (!UCI_EncryptUpdate(st->cipher_ctx, pucOutput, &out_len, pucInput, uiInputLength))
            return SDR_SYMOPERR;
    } else {
        if (!UCI_DecryptUpdate(st->cipher_ctx, pucOutput, &out_len, pucInput, uiInputLength))
            return SDR_SYMOPERR;
    }

    *puiOutputLength = (ULONG)out_len;
    return SDR_OK;
}

LONG SDFU_SymFinal(HANDLE hSymHandle,
                  BYTE *pucOutput,
                  ULONG *puiOutputLength,
                  BYTE *pucTag,
                  ULONG *puiTagLength)
{
    SDF_SYM_STREAM_OBJ *st = (SDF_SYM_STREAM_OBJ *)hSymHandle;
    int out_len = 0;
    size_t mac_len = 0;
    LONG rc = SDR_OK;

    if (st == NULL)
        return SDR_INARGERR;

    if (st->kind == SDF_STREAM_KIND_MAC) {
        if (pucOutput == NULL || puiOutputLength == NULL) {
            rc = SDR_OUTARGERR;
            goto end;
        }

        if (!UCI_MAC_final(st->mac_ctx,
                           pucOutput,
                           &mac_len,
                           *puiOutputLength)) {
            rc = SDR_MACERR;
            goto end;
        }
        *puiOutputLength = (ULONG)mac_len;
        goto end;
    }

    if (pucOutput == NULL || puiOutputLength == NULL) {
        rc = SDR_OUTARGERR;
        goto end;
    }

    if (st->custom_cipher_kind != SDF_CUSTOM_CIPHER_NONE) {
        *puiOutputLength = 0;
        if (pucTag != NULL && puiTagLength != NULL && *puiTagLength > 0)
            memset(pucTag, 0, *puiTagLength);
        goto end;
    }

    if (st->op == SDFU_SYM_OP_ENCRYPT || st->op == SDFU_SYM_OP_AUTH_ENCRYPT) {
        if (!UCI_EncryptFinal_ex(st->cipher_ctx, pucOutput, &out_len)) {
            rc = SDR_SYMOPERR;
            goto end;
        }
        *puiOutputLength = (ULONG)out_len;

        if (st->is_aead && pucTag != NULL && puiTagLength != NULL && *puiTagLength > 0) {
            if (!UCI_CIPHER_CTX_ctrl(st->cipher_ctx,
                                     EVP_CTRL_AEAD_GET_TAG,
                                     *puiTagLength,
                                     pucTag)) {
                rc = SDR_SYMOPERR;
                goto end;
            }
        }
    } else {
        if (!UCI_DecryptFinal_ex(st->cipher_ctx, pucOutput, &out_len)) {
            rc = SDR_SYMOPERR;
            goto end;
        }
        *puiOutputLength = (ULONG)out_len;
    }

end:
    if (st->cipher_ctx != NULL)
        UCI_CIPHER_CTX_free(st->cipher_ctx);
    if (st->mac_ctx != NULL)
        UCI_MAC_CTX_free(st->mac_ctx);
    OPENSSL_clear_free(st->xor_key, st->xor_key_len);
    free(st);
    return rc;
}

LONG SDFU_ExecuteHash(HANDLE hSessionHandle,
                     const SDFU_HASH_REQUEST *pstRequest,
                     SDFU_HASH_RESPONSE *pstResponse)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_KEY_OBJ *key;
    UCI_MAC *mac = NULL;
    UCI_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    size_t out_len = 0;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pstRequest == NULL || pstResponse == NULL ||
        pstResponse->pucOutput == NULL || pstResponse->puiOutputLength == NULL)
        return SDR_OUTARGERR;

    if (pstRequest->uiOperation == SDFU_HASH_OP_DIGEST) {
        out_len = *pstResponse->puiOutputLength;
        if (!UCI_Q_digest(sess->device->libctx,
                          (const char *)pstRequest->pucAlgorithm,
                          (const char *)pstRequest->pucProperties,
                          pstRequest->pucInput,
                          pstRequest->uiInputLength,
                          pstResponse->pucOutput,
                          &out_len)) {
            return SDR_SYMOPERR;
        }
        *pstResponse->puiOutputLength = (ULONG)out_len;
        return SDR_OK;
    }

    if (pstRequest->uiOperation != SDFU_HASH_OP_HMAC)
        return SDR_NOTSUPPORT;

    key = get_key(pstRequest->hKeyHandle);
    if (!ensure_sym_key(key))
        return SDR_KEYTYPEERR;

    mac = UCI_MAC_fetch(sess->device->libctx, "HMAC", pstRequest->pucProperties);
    if (mac == NULL)
        return SDR_ALGNOTSUPPORT;

    ctx = UCI_MAC_CTX_new(mac);
    UCI_MAC_free(mac);
    if (ctx == NULL)
        return SDR_NOBUFFER;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                  (void *)(pstRequest->pucAlgorithm == NULL ? "SHA256" : pstRequest->pucAlgorithm),
                                                  0);
    params[1] = OSSL_PARAM_construct_end();

    if (!UCI_MAC_init(ctx, key->u.sym.bytes, key->u.sym.len, params) ||
        !UCI_MAC_update(ctx, pstRequest->pucInput, pstRequest->uiInputLength) ||
        !UCI_MAC_final(ctx,
                       pstResponse->pucOutput,
                       &out_len,
                       *pstResponse->puiOutputLength)) {
        UCI_MAC_CTX_free(ctx);
        return SDR_MACERR;
    }

    *pstResponse->puiOutputLength = (ULONG)out_len;
    UCI_MAC_CTX_free(ctx);
    return SDR_OK;
}

LONG SDFU_HashInit(HANDLE hSessionHandle,
                  const SDFU_HASH_REQUEST *pstRequest,
                  HANDLE *phHashHandle)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_HASH_STREAM_OBJ *st;
    SDF_KEY_OBJ *key;
    UCI_MAC *mac = NULL;
    UCI_MD *md = NULL;
    OSSL_PARAM params[2];

    if (sess == NULL)
        return SDR_INARGERR;
    if (pstRequest == NULL || phHashHandle == NULL)
        return SDR_OUTARGERR;

    *phHashHandle = NULL;

    st = calloc(1, sizeof(*st));
    if (st == NULL)
        return SDR_NOBUFFER;

    if (pstRequest->uiOperation == SDFU_HASH_OP_DIGEST) {
        st->kind = SDF_HASH_STREAM_DIGEST;
        st->md_ctx = UCI_MD_CTX_new();
        if (st->md_ctx == NULL) {
            free(st);
            return SDR_NOBUFFER;
        }

        md = UCI_MD_fetch(sess->device->libctx,
                          (const char *)pstRequest->pucAlgorithm,
                          (const char *)pstRequest->pucProperties);
        if (md == NULL || !UCI_DigestInit_ex(st->md_ctx, md, NULL)) {
            UCI_MD_free(md);
            UCI_MD_CTX_free(st->md_ctx);
            free(st);
            return SDR_ALGNOTSUPPORT;
        }
        UCI_MD_free(md);
    } else if (pstRequest->uiOperation == SDFU_HASH_OP_HMAC) {
        st->kind = SDF_HASH_STREAM_HMAC;
        key = get_key(pstRequest->hKeyHandle);
        if (!ensure_sym_key(key)) {
            free(st);
            return SDR_KEYTYPEERR;
        }

        mac = UCI_MAC_fetch(sess->device->libctx, "HMAC", pstRequest->pucProperties);
        if (mac == NULL) {
            free(st);
            return SDR_ALGNOTSUPPORT;
        }
        st->mac_ctx = UCI_MAC_CTX_new(mac);
        UCI_MAC_free(mac);
        if (st->mac_ctx == NULL) {
            free(st);
            return SDR_NOBUFFER;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                      (void *)(pstRequest->pucAlgorithm == NULL ? "SHA256" : pstRequest->pucAlgorithm),
                                                      0);
        params[1] = OSSL_PARAM_construct_end();

        if (!UCI_MAC_init(st->mac_ctx, key->u.sym.bytes, key->u.sym.len, params)) {
            UCI_MAC_CTX_free(st->mac_ctx);
            free(st);
            return SDR_MACERR;
        }
    } else {
        free(st);
        return SDR_NOTSUPPORT;
    }

    *phHashHandle = (HANDLE)st;
    return SDR_OK;
}

LONG SDFU_HashUpdate(HANDLE hHashHandle,
                    const BYTE *pucInput,
                    ULONG uiInputLength)
{
    SDF_HASH_STREAM_OBJ *st = (SDF_HASH_STREAM_OBJ *)hHashHandle;

    if (st == NULL)
        return SDR_INARGERR;

    if (st->kind == SDF_HASH_STREAM_DIGEST) {
        if (!UCI_DigestUpdate(st->md_ctx, pucInput, uiInputLength))
            return SDR_SYMOPERR;
        return SDR_OK;
    }

    if (st->kind == SDF_HASH_STREAM_HMAC) {
        if (!UCI_MAC_update(st->mac_ctx, pucInput, uiInputLength))
            return SDR_MACERR;
        return SDR_OK;
    }

    return SDR_NOTSUPPORT;
}

LONG SDFU_HashFinal(HANDLE hHashHandle,
                   BYTE *pucHash,
                   ULONG *puiHashLength)
{
    SDF_HASH_STREAM_OBJ *st = (SDF_HASH_STREAM_OBJ *)hHashHandle;
    unsigned int md_len = 0;
    size_t mac_len = 0;
    LONG rc = SDR_OK;

    if (st == NULL)
        return SDR_INARGERR;
    if (pucHash == NULL || puiHashLength == NULL)
        return SDR_OUTARGERR;

    if (st->kind == SDF_HASH_STREAM_DIGEST) {
        if (!UCI_DigestFinal_ex(st->md_ctx, pucHash, &md_len)) {
            rc = SDR_SYMOPERR;
            goto end;
        }
        *puiHashLength = md_len;
        goto end;
    }

    if (st->kind == SDF_HASH_STREAM_HMAC) {
        if (!UCI_MAC_final(st->mac_ctx, pucHash, &mac_len, *puiHashLength)) {
            rc = SDR_MACERR;
            goto end;
        }
        *puiHashLength = (ULONG)mac_len;
        goto end;
    }

    rc = SDR_NOTSUPPORT;

end:
    if (st->md_ctx != NULL)
        UCI_MD_CTX_free(st->md_ctx);
    if (st->mac_ctx != NULL)
        UCI_MAC_CTX_free(st->mac_ctx);
    free(st);
    return rc;
}

LONG SDF_CreateFile(HANDLE hSessionHandle, LPSTR pucFileName,
                    ULONG uiNameLen, ULONG uiFileSize)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_DEVICE_OBJ *dev;
    SDF_FILE_NODE *node;
    char *name = NULL;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucFileName == NULL || uiNameLen == 0)
        return SDR_INARGERR;

    dev = sess->device;
    if (!copy_name(pucFileName, uiNameLen, &name))
        return SDR_NOBUFFER;

    if (find_file(dev, name) != NULL) {
        free(name);
        return SDR_FILEEXISTS;
    }

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        free(name);
        return SDR_NOBUFFER;
    }

    node->name = name;
    node->size = uiFileSize;
    node->data = calloc(1, node->size);
    if (node->data == NULL && node->size > 0) {
        free(node->name);
        free(node);
        return SDR_NOBUFFER;
    }

    node->next = dev->files;
    dev->files = node;
    return SDR_OK;
}

LONG SDF_ReadFile(HANDLE hSessionHandle, LPSTR pucFileName,
                  ULONG uiNameLen, ULONG uiOffset,
                  ULONG *puiReadLength, BYTE *pucBuffer)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_FILE_NODE *node;
    char *name = NULL;
    size_t read_len;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucFileName == NULL || uiNameLen == 0 || puiReadLength == NULL || pucBuffer == NULL)
        return SDR_INARGERR;

    if (!copy_name(pucFileName, uiNameLen, &name))
        return SDR_NOBUFFER;

    node = find_file(sess->device, name);
    free(name);
    if (node == NULL)
        return SDR_FILENOEXIST;

    if ((size_t)uiOffset > node->size)
        return SDR_FILEOFSERR;

    read_len = *puiReadLength;
    if ((size_t)uiOffset + read_len > node->size)
        read_len = node->size - (size_t)uiOffset;

    memcpy(pucBuffer, node->data + uiOffset, read_len);
    *puiReadLength = (ULONG)read_len;
    return SDR_OK;
}

LONG SDF_WriteFile(HANDLE hSessionHandle, LPSTR pucFileName,
                   ULONG uiNameLen, ULONG uiOffset,
                   ULONG uiWriteLength, BYTE *pucBuffer)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_FILE_NODE *node;
    char *name = NULL;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucFileName == NULL || uiNameLen == 0 || pucBuffer == NULL)
        return SDR_INARGERR;

    if (!copy_name(pucFileName, uiNameLen, &name))
        return SDR_NOBUFFER;

    node = find_file(sess->device, name);
    free(name);
    if (node == NULL)
        return SDR_FILENOEXIST;

    if ((size_t)uiOffset > node->size)
        return SDR_FILEOFSERR;
    if ((size_t)uiOffset + (size_t)uiWriteLength > node->size)
        return SDR_FILESIZEERR;

    memcpy(node->data + uiOffset, pucBuffer, uiWriteLength);
    return SDR_OK;
}

LONG SDF_DeleteFile(HANDLE hSessionHandle, LPSTR pucFileName,
                    ULONG uiNameLen)
{
    SDF_SESSION_OBJ *sess = get_session(hSessionHandle);
    SDF_FILE_NODE *cur;
    SDF_FILE_NODE *prev = NULL;
    char *name = NULL;

    if (sess == NULL)
        return SDR_INARGERR;
    if (pucFileName == NULL || uiNameLen == 0)
        return SDR_INARGERR;

    if (!copy_name(pucFileName, uiNameLen, &name))
        return SDR_NOBUFFER;

    cur = sess->device->files;
    while (cur != NULL) {
        if (strcmp(cur->name, name) == 0) {
            if (prev == NULL)
                sess->device->files = cur->next;
            else
                prev->next = cur->next;

            free(cur->name);
            free(cur->data);
            free(cur);
            free(name);
            return SDR_OK;
        }
        prev = cur;
        cur = cur->next;
    }

    free(name);
    return SDR_FILENOEXIST;
}
