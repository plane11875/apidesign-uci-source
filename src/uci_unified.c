#include <string.h>
#include <stdint.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include "uci/uci_unified.h"

#define UCI_PUBKEY_BLOB_MAGIC "UCPK"
#define UCI_PUBKEY_BLOB_VERSION 1u
#define UCI_PUBKEY_HEADER_LEN 11u

static int is_empty(const char *s)
{
    return s == NULL || *s == '\0';
}

static void store_u16_be(unsigned char *out, uint16_t v)
{
    out[0] = (unsigned char)((v >> 8) & 0xFFu);
    out[1] = (unsigned char)(v & 0xFFu);
}

static uint16_t load_u16_be(const unsigned char *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static void store_u32_be(unsigned char *out, uint32_t v)
{
    out[0] = (unsigned char)((v >> 24) & 0xFFu);
    out[1] = (unsigned char)((v >> 16) & 0xFFu);
    out[2] = (unsigned char)((v >> 8) & 0xFFu);
    out[3] = (unsigned char)(v & 0xFFu);
}

static uint32_t load_u32_be(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

int UCI_KeyGenerate(UCI_LIB_CTX *libctx, const char *algorithm,
                    const char *properties, UCI_PKEY **out_key)
{
    UCI_PKEY_CTX *ctx = NULL;

    if (is_empty(algorithm) || out_key == NULL)
        return 0;

    *out_key = NULL;

    ctx = UCI_PKEY_CTX_new_from_name(libctx, algorithm, properties);
    if (ctx == NULL)
        return 0;

    if (!UCI_PKEY_keygen_init(ctx)) {
        UCI_PKEY_CTX_free(ctx);
        return 0;
    }

    if (!UCI_PKEY_keygen(ctx, out_key)) {
        UCI_PKEY_CTX_free(ctx);
        return 0;
    }

    UCI_PKEY_CTX_free(ctx);
    return 1;
}

int UCI_PublicKeyExport(UCI_PKEY *pkey, unsigned char *der, size_t *der_len)
{
    int needed;
    unsigned char *p;
    const char *alg_name;
    size_t alg_len = 0;
    size_t pub_len = 0;
    size_t total_len = 0;
    unsigned char *cursor = NULL;

    if (pkey == NULL || der_len == NULL)
        return 0;

    /* Preferred format: DER SubjectPublicKeyInfo */
    needed = i2d_PUBKEY(pkey, NULL);
    if (needed > 0) {
        if (der == NULL) {
            *der_len = (size_t)needed;
            return 1;
        }

        if (*der_len < (size_t)needed)
            return 0;

        p = der;
        if (i2d_PUBKEY(pkey, &p) <= 0)
            return 0;

        *der_len = (size_t)needed;
        return 1;
    }

    /*
     * Fallback format for provider keys without SPKI encoder:
     * magic(4) + version(1) + alg_len(2) + pub_len(4) + alg + pubkey_octets
     */
    alg_name = UCI_PKEY_get0_type_name(pkey);
    if (is_empty(alg_name))
        return 0;
    alg_len = strlen(alg_name);
    if (alg_len > 0xFFFFu)
        return 0;

    if (!UCI_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         NULL, 0, &pub_len)) {
        return 0;
    }

    total_len = UCI_PUBKEY_HEADER_LEN + alg_len + pub_len;
    if (der == NULL) {
        *der_len = total_len;
        return 1;
    }
    if (*der_len < total_len)
        return 0;

    cursor = der;
    memcpy(cursor, UCI_PUBKEY_BLOB_MAGIC, 4);
    cursor += 4;
    *cursor++ = UCI_PUBKEY_BLOB_VERSION;
    store_u16_be(cursor, (uint16_t)alg_len);
    cursor += 2;
    store_u32_be(cursor, (uint32_t)pub_len);
    cursor += 4;
    memcpy(cursor, alg_name, alg_len);
    cursor += alg_len;

    if (!UCI_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                         cursor, pub_len, &pub_len)) {
        return 0;
    }

    *der_len = total_len;
    return 1;
}

int UCI_PublicKeyImport(UCI_LIB_CTX *libctx, const char *properties,
                        const unsigned char *der, size_t der_len,
                        UCI_PKEY **out_key)
{
    const unsigned char *p;
    UCI_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char *alg_name = NULL;
    const unsigned char *pub = NULL;
    size_t alg_len = 0;
    size_t pub_len = 0;

    if (der == NULL || der_len == 0 || out_key == NULL)
        return 0;

    *out_key = NULL;

    /* Preferred format: DER SubjectPublicKeyInfo */
    p = der;
    *out_key = d2i_PUBKEY_ex(NULL, &p, (long)der_len, libctx, properties);
    if (*out_key != NULL) {
        /* Ensure all input bytes were consumed. */
        if ((size_t)(p - der) != der_len) {
            UCI_PKEY_free(*out_key);
            *out_key = NULL;
            return 0;
        }
        return 1;
    }

    /* Fallback format: UCPK custom blob */
    if (der_len < UCI_PUBKEY_HEADER_LEN)
        return 0;
    if (memcmp(der, UCI_PUBKEY_BLOB_MAGIC, 4) != 0)
        return 0;
    if (der[4] != UCI_PUBKEY_BLOB_VERSION)
        return 0;

    alg_len = load_u16_be(der + 5);
    pub_len = load_u32_be(der + 7);

    if (alg_len == 0 || pub_len == 0)
        return 0;
    if (UCI_PUBKEY_HEADER_LEN + alg_len + pub_len != der_len)
        return 0;

    alg_name = OPENSSL_zalloc(alg_len + 1);
    if (alg_name == NULL)
        return 0;
    memcpy(alg_name, der + UCI_PUBKEY_HEADER_LEN, alg_len);
    alg_name[alg_len] = '\0';
    pub = der + UCI_PUBKEY_HEADER_LEN + alg_len;

    ctx = UCI_PKEY_CTX_new_from_name(libctx, (const char *)alg_name, properties);
    if (ctx == NULL)
        goto end;
    if (!UCI_PKEY_fromdata_init(ctx))
        goto end;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                   (void *)pub, pub_len);
    params[1] = OSSL_PARAM_construct_end();

    if (!UCI_PKEY_fromdata(ctx, out_key, EVP_PKEY_PUBLIC_KEY, params))
        goto end;

    OPENSSL_free(alg_name);
    UCI_PKEY_CTX_free(ctx);
    return 1;

end:
    OPENSSL_free(alg_name);
    UCI_PKEY_CTX_free(ctx);
    if (*out_key != NULL) {
        UCI_PKEY_free(*out_key);
        *out_key = NULL;
    }
    return 0;
}

static int execute_digest(UCI_UNIFIED_REQUEST *req)
{
    size_t out_len = 0;

    if (is_empty(req->algorithm) || req->output == NULL || req->output_len == NULL)
        return 0;

    out_len = *req->output_len;
    if (!UCI_Q_digest(req->libctx, req->algorithm, req->properties,
                      req->input, req->input_len,
                      req->output, &out_len)) {
        return 0;
    }

    *req->output_len = out_len;
    return 1;
}

static int execute_sign(UCI_UNIFIED_REQUEST *req)
{
    UCI_MD_CTX *md_ctx = NULL;
    UCI_MD *md = NULL;
    int ok = 0;

    if (req->key == NULL || req->output_len == NULL)
        return 0;

    md_ctx = UCI_MD_CTX_new();
    if (md_ctx == NULL)
        return 0;

    if (!is_empty(req->algorithm)) {
        md = UCI_MD_fetch(req->libctx, req->algorithm, req->properties);
        if (md == NULL)
            goto end;
    }

    if (!UCI_DigestSignInit(md_ctx, NULL, md, NULL, req->key))
        goto end;

    if (!UCI_DigestSignUpdate(md_ctx, req->input, req->input_len))
        goto end;

    if (!UCI_DigestSignFinal(md_ctx, req->output, req->output_len))
        goto end;

    ok = 1;

end:
    UCI_MD_free(md);
    UCI_MD_CTX_free(md_ctx);
    return ok;
}

static int execute_verify(UCI_UNIFIED_REQUEST *req)
{
    UCI_MD_CTX *md_ctx = NULL;
    UCI_MD *md = NULL;
    int rc;
    int ok = 0;

    if (req->key == NULL || req->extra_input == NULL || req->extra_input_len == 0)
        return 0;

    req->verify_ok = 0;

    md_ctx = UCI_MD_CTX_new();
    if (md_ctx == NULL)
        return 0;

    if (!is_empty(req->algorithm)) {
        md = UCI_MD_fetch(req->libctx, req->algorithm, req->properties);
        if (md == NULL)
            goto end;
    }

    if (!UCI_DigestVerifyInit(md_ctx, NULL, md, NULL, req->key))
        goto end;

    if (!UCI_DigestVerifyUpdate(md_ctx, req->input, req->input_len))
        goto end;

    rc = UCI_DigestVerifyFinal(md_ctx, req->extra_input, req->extra_input_len);
    if (rc < 0)
        goto end;

    req->verify_ok = (rc == 1);
    ok = 1;

end:
    UCI_MD_free(md);
    UCI_MD_CTX_free(md_ctx);
    return ok;
}

static int execute_kem_encapsulate(UCI_UNIFIED_REQUEST *req)
{
    UCI_PKEY_CTX *ctx = NULL;
    size_t ct_len = 0;
    size_t ss_len = 0;
    int ok = 0;

    if (req->key == NULL || req->output_len == NULL || req->extra_output_len == NULL)
        return 0;

    ctx = UCI_PKEY_CTX_new_from_pkey(req->libctx, req->key, req->properties);
    if (ctx == NULL)
        return 0;

    if (!UCI_PKEY_encapsulate_init(ctx, NULL))
        goto end;

    if (!UCI_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len))
        goto end;

    *req->extra_output_len = ct_len;
    *req->output_len = ss_len;

    if (req->extra_output == NULL || req->output == NULL) {
        ok = 1;
        goto end;
    }

    if (!UCI_PKEY_encapsulate(ctx,
                              req->extra_output, req->extra_output_len,
                              req->output, req->output_len)) {
        goto end;
    }

    ok = 1;

end:
    UCI_PKEY_CTX_free(ctx);
    return ok;
}

static int execute_kem_decapsulate(UCI_UNIFIED_REQUEST *req)
{
    UCI_PKEY_CTX *ctx = NULL;
    size_t ss_len = 0;
    int ok = 0;

    if (req->key == NULL || req->output_len == NULL ||
        req->extra_input == NULL || req->extra_input_len == 0) {
        return 0;
    }

    ctx = UCI_PKEY_CTX_new_from_pkey(req->libctx, req->key, req->properties);
    if (ctx == NULL)
        return 0;

    if (!UCI_PKEY_decapsulate_init(ctx, NULL))
        goto end;

    if (!UCI_PKEY_decapsulate(ctx, NULL, &ss_len, req->extra_input, req->extra_input_len))
        goto end;

    *req->output_len = ss_len;
    if (req->output == NULL) {
        ok = 1;
        goto end;
    }

    if (!UCI_PKEY_decapsulate(ctx, req->output, req->output_len,
                              req->extra_input, req->extra_input_len)) {
        goto end;
    }

    ok = 1;

end:
    UCI_PKEY_CTX_free(ctx);
    return ok;
}

int UCI_Execute(UCI_UNIFIED_REQUEST *req)
{
    if (req == NULL)
        return 0;

    switch (req->operation) {
    case UCI_OPERATION_DIGEST:
        return execute_digest(req);
    case UCI_OPERATION_SIGN:
        return execute_sign(req);
    case UCI_OPERATION_VERIFY:
        return execute_verify(req);
    case UCI_OPERATION_KEM_ENCAPSULATE:
        return execute_kem_encapsulate(req);
    case UCI_OPERATION_KEM_DECAPSULATE:
        return execute_kem_decapsulate(req);
    default:
        return 0;
    }
}
