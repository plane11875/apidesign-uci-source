#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "uci/sdf.h"

#define ALG_MLKEM768_ID   ((ULONG)0x00F0D502u)
#define ALG_FRODO640SHAKE ((ULONG)0x00F0D620u)
#define ALG_EFRODO640AES  ((ULONG)0x00F0D621u)

static void sha256_hex(const BYTE *buf, ULONG len, char out[65])
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    size_t i;

    if (ctx == NULL || buf == NULL || len == 0 ||
        EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, buf, (size_t)len) != 1 ||
        EVP_DigestFinal_ex(ctx, md, &md_len) != 1) {
        snprintf(out, 65, "ERR");
        if (ctx)
            EVP_MD_CTX_free(ctx);
        return;
    }

    for (i = 0; i < (size_t)md_len && i < 32; ++i)
        sprintf(out + i * 2, "%02x", md[i]);
    out[64] = '\0';
    EVP_MD_CTX_free(ctx);
}

static int write_patch_file(const char *path, ULONG algid,
                            const char *alg, const char *provider)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return 0;
    fprintf(fp, "0x%08X %s provider=%s\n", algid, alg, provider);
    fclose(fp);
    return 1;
}

typedef struct {
    const char *name;
    ULONG algid;
} KEM_ALG;

static int write_patch_file_all(const char *path, const KEM_ALG *algs, size_t n, const char *provider)
{
    size_t i;
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return 0;
    for (i = 0; i < n; ++i)
        fprintf(fp, "0x%08X %s provider=%s\n", algs[i].algid, algs[i].name, provider);
    fclose(fp);
    return 1;
}

static int run_one(HANDLE sess, const KEM_ALG *a)
{
    LONG rc;
    HANDLE prov = NULL, sk = NULL, pub = NULL;
    HANDLE old_k = NULL, new_k = NULL, imp_k = NULL;
    BYTE *pub_blob = NULL;
    ULONG pub_len = 0;

    BYTE *ct_old = NULL, *ct_new = NULL;
    ULONG ct_old_len = 0, ct_new_len = 0;

    BYTE ss_old[8192], ss_new[8192], ss_imp[8192];
    ULONG ss_old_len = sizeof(ss_old), ss_new_len = sizeof(ss_new), ss_imp_len = sizeof(ss_imp);

    SDFR_REQUEST req;
    SDFR_RESPONSE rsp;

    char h_ct_old[65], h_ct_new[65], h_ss_old[65], h_ss_new[65], h_ss_imp[65];
    int ok = 0;

    const char *patch = "/tmp/equiv_matrix_patch.conf";
    char props[128];

    snprintf(props, sizeof(props), "provider=oqsprovider");
    setenv("SDFR_PATCH_FILE", patch, 1);

    rc = SDFU_LoadProvider(sess, (const CHAR *)"oqsprovider", &prov);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] %s load provider rc=0x%08X\n", a->name, (unsigned)rc);
        goto out;
    }

    rc = SDFU_GenerateKeyPair(sess, (const CHAR *)a->name, (const CHAR *)props, &sk);
    if (rc != SDR_OK) {
        fprintf(stderr, "[FAIL] %s keygen rc=0x%08X\n", a->name, (unsigned)rc);
        goto out;
    }

    rc = SDFU_ExportPublicKey(sess, sk, NULL, &pub_len);
    if (rc != SDR_OK || pub_len == 0)
        goto out;
    pub_blob = (BYTE *)malloc(pub_len);
    if (!pub_blob)
        goto out;
    rc = SDFU_ExportPublicKey(sess, sk, pub_blob, &pub_len);
    if (rc != SDR_OK)
        goto out;
    rc = SDFU_ImportPublicKey(sess, pub_blob, pub_len, (const CHAR *)props, &pub);
    if (rc != SDR_OK)
        goto out;

    rc = SDF_GenerateKeyWithEPK(sess, 256, a->algid, pub, NULL, &ct_old_len, &old_k);
    if (rc != SDR_OUTARGERR || ct_old_len == 0)
        goto out;
    ct_old = (BYTE *)malloc(ct_old_len);
    if (!ct_old)
        goto out;
    rc = SDF_GenerateKeyWithEPK(sess, 256, a->algid, pub, ct_old, &ct_old_len, &old_k);
    if (rc != SDR_OK)
        goto out;

    rc = SDF_GenerateKeyWithIPK(sess, 0, 256, a->algid, pub, NULL, &ct_new_len, &new_k);
    if (rc != SDR_OUTARGERR || ct_new_len == 0)
        goto out;
    ct_new = (BYTE *)malloc(ct_new_len);
    if (!ct_new)
        goto out;
    rc = SDF_GenerateKeyWithIPK(sess, 0, 256, a->algid, pub, ct_new, &ct_new_len, &new_k);
    if (rc != SDR_OK)
        goto out;

    memset(&req, 0, sizeof(req)); memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_DECAPSULATE; req.uiAlgID = a->algid; req.hKeyHandle = sk;
    req.pucExtraInput = ct_old; req.uiExtraInputLength = ct_old_len;
    rsp.pucOutput = ss_old; rsp.puiOutputLength = &ss_old_len;
    rc = SDFR_Execute(sess, &req, &rsp); if (rc != SDR_OK) goto out;

    memset(&req, 0, sizeof(req)); memset(&rsp, 0, sizeof(rsp));
    req.uiOperation = SDFR_OP_KEM_DECAPSULATE; req.uiAlgID = a->algid; req.hKeyHandle = sk;
    req.pucExtraInput = ct_new; req.uiExtraInputLength = ct_new_len;
    rsp.pucOutput = ss_new; rsp.puiOutputLength = &ss_new_len;
    rc = SDFR_Execute(sess, &req, &rsp); if (rc != SDR_OK) goto out;

    rc = SDF_ImportKeyWithISK(sess, 0, a->algid, sk, ct_old, ct_old_len, &imp_k);
    if (rc != SDR_OK) goto out;

    {
        BYTE zero_iv[16] = {0};
        BYTE enc[8192], dec[8192];
        ULONG enc_len = sizeof(enc), dec_len = sizeof(dec);
        SDFU_SYM_REQUEST q; SDFU_SYM_RESPONSE s;

        memset(&q,0,sizeof(q)); memset(&s,0,sizeof(s));
        q.uiOperation=SDFU_SYM_OP_ENCRYPT; q.pucAlgorithm=(const CHAR*)"SM4-CBC";
        q.hKeyHandle=imp_k; q.pucIV=zero_iv; q.uiIVLength=sizeof(zero_iv);
        q.pucInput=ss_old; q.uiInputLength=ss_old_len;
        s.pucOutput=enc; s.puiOutputLength=&enc_len;
        rc=SDFU_ExecuteSymmetric(sess,&q,&s); if(rc!=SDR_OK) goto out;

        memset(&q,0,sizeof(q)); memset(&s,0,sizeof(s));
        q.uiOperation=SDFU_SYM_OP_DECRYPT; q.pucAlgorithm=(const CHAR*)"SM4-CBC";
        q.hKeyHandle=imp_k; q.pucIV=zero_iv; q.uiIVLength=sizeof(zero_iv);
        q.pucInput=enc; q.uiInputLength=enc_len;
        s.pucOutput=dec; s.puiOutputLength=&dec_len;
        rc=SDFU_ExecuteSymmetric(sess,&q,&s); if(rc!=SDR_OK) goto out;

        if (dec_len != ss_old_len || memcmp(dec, ss_old, ss_old_len) != 0)
            goto out;
        memcpy(ss_imp, dec, dec_len); ss_imp_len = dec_len;
    }

    sha256_hex(ct_old, ct_old_len, h_ct_old);
    sha256_hex(ct_new, ct_new_len, h_ct_new);
    sha256_hex(ss_old, ss_old_len, h_ss_old);
    sha256_hex(ss_new, ss_new_len, h_ss_new);
    sha256_hex(ss_imp, ss_imp_len, h_ss_imp);

    printf("[%s] old_epk.ct=%s(%u) | new_ipk.ct=%s(%u) | old_ss=%s(%u) | new_ss=%s(%u) | isk_ss=%s(%u)\n",
           a->name,
           h_ct_old, (unsigned)ct_old_len,
           h_ct_new, (unsigned)ct_new_len,
           h_ss_old, (unsigned)ss_old_len,
           h_ss_new, (unsigned)ss_new_len,
           h_ss_imp, (unsigned)ss_imp_len);

    ok = 1;
out:
    if (!ok)
        printf("[%s] FAIL rc=0x%08X\n", a->name, (unsigned)rc);
    if (imp_k) (void)SDF_DestroyKey(sess, imp_k);
    if (old_k) (void)SDF_DestroyKey(sess, old_k);
    if (new_k) (void)SDF_DestroyKey(sess, new_k);
    if (pub) (void)SDF_DestroyKey(sess, pub);
    if (sk) (void)SDF_DestroyKey(sess, sk);
    if (prov) (void)SDFU_UnloadProvider(prov);
    if (ct_old) free(ct_old);
    if (ct_new) free(ct_new);
    if (pub_blob) free(pub_blob);
    return ok;
}

int main(void)
{
    HANDLE dev = NULL, sess = NULL;
    LONG rc;
    int ok = 1;
    const char *patch = "/tmp/equiv_matrix_patch.conf";
    const KEM_ALG algs[] = {
        {"mlkem768", ALG_MLKEM768_ID},
        {"frodo640shake", ALG_FRODO640SHAKE},
        {"efrodo640aes", ALG_EFRODO640AES},
    };
    size_t i;

    if (!write_patch_file_all(patch, algs, sizeof(algs)/sizeof(algs[0]), "oqsprovider")) {
        fprintf(stderr, "[FAIL] cannot write patch file\n");
        return 1;
    }
    setenv("SDFR_PATCH_FILE", patch, 1);

    rc = SDF_OpenDevice(&dev);
    if (rc != SDR_OK) return 2;
    rc = SDF_OpenSession(dev, &sess);
    if (rc != SDR_OK) { SDF_CloseDevice(dev); return 2; }

    for (i = 0; i < sizeof(algs)/sizeof(algs[0]); ++i)
        ok = run_one(sess, &algs[i]) && ok;

    SDF_CloseSession(sess);
    SDF_CloseDevice(dev);
    unlink(patch);
    return ok ? 0 : 1;
}
