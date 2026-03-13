/*
 * UCI 混合密码服务实现
 * 经典算法 + 抗量子算法的混合模式
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "uci/uci_hybrid.h"

/* 混合签名上下文结构 */
struct uci_hybrid_sign_ctx_st {
    UCI_PKEY *classical_key;
    UCI_PKEY *pqc_key;
};

/* 混合 KEM 上下文结构 */
struct uci_hybrid_kem_ctx_st {
    UCI_PKEY *classical_key;
    UCI_PKEY *pqc_key;
};

/* 混合签名接口实现 */
UCI_HYBRID_SIGN_CTX *UCI_HYBRID_SIGN_CTX_new(void) {
    return calloc(1, sizeof(UCI_HYBRID_SIGN_CTX));
}

void UCI_HYBRID_SIGN_CTX_free(UCI_HYBRID_SIGN_CTX *ctx) {
    if (ctx) {
        free(ctx);
    }
}

int UCI_HYBRID_SIGN_init(UCI_HYBRID_SIGN_CTX *ctx,
                         UCI_PKEY *classical_key,
                         UCI_PKEY *pqc_key) {
    if (!ctx || !classical_key || !pqc_key)
        return 0;

    ctx->classical_key = classical_key;
    ctx->pqc_key = pqc_key;
    return 1;
}

int UCI_HYBRID_sign(UCI_HYBRID_SIGN_CTX *ctx,
                    unsigned char *sig, size_t *siglen,
                    const unsigned char *msg, size_t msglen) {
    if (!ctx || !ctx->classical_key || !ctx->pqc_key)
        return 0;

    /* 经典签名 */
    UCI_MD_CTX *classical_ctx = UCI_MD_CTX_new();
    if (!UCI_DigestSignInit(classical_ctx, NULL, NULL, NULL, ctx->classical_key))
        goto err;

    if (!UCI_DigestSignUpdate(classical_ctx, msg, msglen))
        goto err;

    size_t classical_siglen = 0;
    if (!UCI_DigestSignFinal(classical_ctx, NULL, &classical_siglen))
        goto err;

    unsigned char *classical_sig = malloc(classical_siglen);
    if (!UCI_DigestSignFinal(classical_ctx, classical_sig, &classical_siglen))
        goto err_free;

    UCI_MD_CTX_free(classical_ctx);

    /* 抗量子签名 */
    UCI_MD_CTX *pqc_ctx = UCI_MD_CTX_new();
    if (!UCI_DigestSignInit(pqc_ctx, NULL, NULL, NULL, ctx->pqc_key))
        goto err_free;

    if (!UCI_DigestSignUpdate(pqc_ctx, msg, msglen))
        goto err_free;

    size_t pqc_siglen = 0;
    if (!UCI_DigestSignFinal(pqc_ctx, NULL, &pqc_siglen))
        goto err_free;

    unsigned char *pqc_sig = malloc(pqc_siglen);
    if (!UCI_DigestSignFinal(pqc_ctx, pqc_sig, &pqc_siglen))
        goto err_free2;

    UCI_MD_CTX_free(pqc_ctx);

    /* 组合签名: [classical_siglen(4字节)][classical_sig][pqc_sig] */
    size_t total_len = 4 + classical_siglen + pqc_siglen;

    if (sig == NULL) {
        *siglen = total_len;
        free(classical_sig);
        free(pqc_sig);
        return 1;
    }

    if (*siglen < total_len) {
        free(classical_sig);
        free(pqc_sig);
        return 0;
    }

    /* 写入长度 */
    sig[0] = (classical_siglen >> 24) & 0xFF;
    sig[1] = (classical_siglen >> 16) & 0xFF;
    sig[2] = (classical_siglen >> 8) & 0xFF;
    sig[3] = classical_siglen & 0xFF;

    memcpy(sig + 4, classical_sig, classical_siglen);
    memcpy(sig + 4 + classical_siglen, pqc_sig, pqc_siglen);

    *siglen = total_len;

    free(classical_sig);
    free(pqc_sig);
    return 1;

err_free2:
    free(pqc_sig);
err_free:
    free(classical_sig);
err:
    UCI_MD_CTX_free(classical_ctx);
    return 0;
}

int UCI_HYBRID_verify(UCI_HYBRID_SIGN_CTX *ctx,
                      const unsigned char *sig, size_t siglen,
                      const unsigned char *msg, size_t msglen) {
    if (!ctx || !sig || siglen < 4)
        return 0;

    /* 解析签名 */
    size_t classical_siglen = ((size_t)sig[0] << 24) |
                              ((size_t)sig[1] << 16) |
                              ((size_t)sig[2] << 8) |
                              (size_t)sig[3];

    if (siglen < 4 + classical_siglen)
        return 0;

    const unsigned char *classical_sig = sig + 4;
    const unsigned char *pqc_sig = sig + 4 + classical_siglen;
    size_t pqc_siglen = siglen - 4 - classical_siglen;

    /* 验证经典签名 */
    UCI_MD_CTX *classical_ctx = UCI_MD_CTX_new();
    if (!UCI_DigestVerifyInit(classical_ctx, NULL, NULL, NULL, ctx->classical_key))
        goto err;

    if (!UCI_DigestVerifyUpdate(classical_ctx, msg, msglen))
        goto err;

    if (!UCI_DigestVerifyFinal(classical_ctx, classical_sig, classical_siglen))
        goto err;

    UCI_MD_CTX_free(classical_ctx);

    /* 验证抗量子签名 */
    UCI_MD_CTX *pqc_ctx = UCI_MD_CTX_new();
    if (!UCI_DigestVerifyInit(pqc_ctx, NULL, NULL, NULL, ctx->pqc_key))
        goto err2;

    if (!UCI_DigestVerifyUpdate(pqc_ctx, msg, msglen))
        goto err2;

    if (!UCI_DigestVerifyFinal(pqc_ctx, pqc_sig, pqc_siglen))
        goto err2;

    UCI_MD_CTX_free(pqc_ctx);
    return 1;

err2:
    UCI_MD_CTX_free(pqc_ctx);
    return 0;
err:
    UCI_MD_CTX_free(classical_ctx);
    return 0;
}

/* 混合 KEM 接口实现 */
UCI_HYBRID_KEM_CTX *UCI_HYBRID_KEM_CTX_new(void) {
    return calloc(1, sizeof(UCI_HYBRID_KEM_CTX));
}

void UCI_HYBRID_KEM_CTX_free(UCI_HYBRID_KEM_CTX *ctx) {
    if (ctx) {
        free(ctx);
    }
}

int UCI_HYBRID_KEM_init(UCI_HYBRID_KEM_CTX *ctx,
                        UCI_PKEY *classical_key,
                        UCI_PKEY *pqc_key) {
    if (!ctx || !classical_key || !pqc_key)
        return 0;

    ctx->classical_key = classical_key;
    ctx->pqc_key = pqc_key;
    return 1;
}

int UCI_HYBRID_encapsulate(UCI_HYBRID_KEM_CTX *ctx,
                           unsigned char *ct, size_t *ctlen,
                           unsigned char *ss, size_t *sslen) {
    if (!ctx || !ctx->classical_key || !ctx->pqc_key)
        return 0;

    /* 经典算法使用 derive (X25519/ECDH) */
    /* 1. 生成临时密钥对 */
    UCI_PKEY_CTX *keygen_ctx = UCI_PKEY_CTX_new_from_pkey(NULL, ctx->classical_key, NULL);
    if (!UCI_PKEY_keygen_init(keygen_ctx))
        goto err;

    UCI_PKEY *ephemeral_key = NULL;
    if (!UCI_PKEY_keygen(keygen_ctx, &ephemeral_key))
        goto err;
    UCI_PKEY_CTX_free(keygen_ctx);

    /* 2. 使用临时私钥和对方公钥进行 derive */
    UCI_PKEY_CTX *derive_ctx = UCI_PKEY_CTX_new_from_pkey(NULL, ephemeral_key, NULL);
    if (!UCI_PKEY_derive_init(derive_ctx))
        goto err_ephemeral;

    if (!UCI_PKEY_derive_set_peer(derive_ctx, ctx->classical_key))
        goto err_ephemeral;

    size_t classical_sslen = 0;
    if (!UCI_PKEY_derive(derive_ctx, NULL, &classical_sslen))
        goto err_ephemeral;

    unsigned char *classical_ss = malloc(classical_sslen);
    if (!UCI_PKEY_derive(derive_ctx, classical_ss, &classical_sslen))
        goto err_free_ss;
    UCI_PKEY_CTX_free(derive_ctx);

    /* 3. 获取临时公钥作为密文 */
    size_t classical_ctlen = 0;
    unsigned char *classical_ct = NULL;
    classical_ctlen = EVP_PKEY_get1_encoded_public_key(ephemeral_key, &classical_ct);
    if (classical_ctlen == 0 || !classical_ct)
        goto err_free_ss;

    /* 抗量子 KEM 封装 */
    UCI_PKEY_CTX *pqc_ctx = UCI_PKEY_CTX_new_from_pkey(NULL, ctx->pqc_key, NULL);
    if (!UCI_PKEY_encapsulate_init(pqc_ctx, NULL))
        goto err_free;

    size_t pqc_ctlen = 0, pqc_sslen = 0;
    if (!UCI_PKEY_encapsulate(pqc_ctx, NULL, &pqc_ctlen, NULL, &pqc_sslen))
        goto err_free;

    unsigned char *pqc_ct = malloc(pqc_ctlen);
    unsigned char *pqc_ss = malloc(pqc_sslen);

    if (!UCI_PKEY_encapsulate(pqc_ctx, pqc_ct, &pqc_ctlen, pqc_ss, &pqc_sslen))
        goto err_free2;

    UCI_PKEY_CTX_free(pqc_ctx);

    /* 组合密文: [classical_ctlen(4字节)][classical_ct][pqc_ct] */
    size_t total_ctlen = 4 + classical_ctlen + pqc_ctlen;

    if (ct == NULL) {
        *ctlen = total_ctlen;
        *sslen = 32; /* 使用 SHA256 组合共享密钥 */
        free(classical_ct);
        free(classical_ss);
        free(pqc_ct);
        free(pqc_ss);
        return 1;
    }

    if (*ctlen < total_ctlen) {
        free(classical_ct);
        free(classical_ss);
        free(pqc_ct);
        free(pqc_ss);
        return 0;
    }

    /* 写入密文 */
    ct[0] = (classical_ctlen >> 24) & 0xFF;
    ct[1] = (classical_ctlen >> 16) & 0xFF;
    ct[2] = (classical_ctlen >> 8) & 0xFF;
    ct[3] = classical_ctlen & 0xFF;

    memcpy(ct + 4, classical_ct, classical_ctlen);
    memcpy(ct + 4 + classical_ctlen, pqc_ct, pqc_ctlen);
    *ctlen = total_ctlen;

    /* 组合共享密钥: SHA256(classical_ss || pqc_ss) */
    UCI_MD_CTX *md_ctx = UCI_MD_CTX_new();
    UCI_DigestInit_ex(md_ctx, UCI_sha256(), NULL);
    UCI_DigestUpdate(md_ctx, classical_ss, classical_sslen);
    UCI_DigestUpdate(md_ctx, pqc_ss, pqc_sslen);
    unsigned int final_sslen = 0;
    UCI_DigestFinal_ex(md_ctx, ss, &final_sslen);
    UCI_MD_CTX_free(md_ctx);

    *sslen = final_sslen;

    free(classical_ct);
    free(classical_ss);
    free(pqc_ct);
    free(pqc_ss);
    UCI_PKEY_free(ephemeral_key);
    return 1;

err_free2:
    free(pqc_ct);
    free(pqc_ss);
err_free:
    OPENSSL_free(classical_ct);
err_free_ss:
    free(classical_ss);
err_ephemeral:
    UCI_PKEY_free(ephemeral_key);
err:
    return 0;
}

int UCI_HYBRID_decapsulate(UCI_HYBRID_KEM_CTX *ctx,
                           unsigned char *ss, size_t *sslen,
                           const unsigned char *ct, size_t ctlen) {
    if (!ctx || !ct || ctlen < 4)
        return 0;

    /* 如果只是查询长度 */
    if (ss == NULL) {
        *sslen = 32; /* SHA256 输出长度 */
        return 1;
    }

    /* 解析密文 */
    size_t classical_ctlen = ((size_t)ct[0] << 24) |
                             ((size_t)ct[1] << 16) |
                             ((size_t)ct[2] << 8) |
                             (size_t)ct[3];

    if (ctlen < 4 + classical_ctlen)
        return 0;

    const unsigned char *classical_ct = ct + 4;
    const unsigned char *pqc_ct = ct + 4 + classical_ctlen;
    size_t pqc_ctlen = ctlen - 4 - classical_ctlen;

    /* 经典算法使用 derive (X25519/ECDH) */
    /* 1. 从密文恢复对方临时公钥 */
    UCI_PKEY *peer_key = UCI_PKEY_new();
    if (!peer_key)
        goto err;

    if (!EVP_PKEY_copy_parameters(peer_key, ctx->classical_key))
        goto err_peer;

    if (!EVP_PKEY_set1_encoded_public_key(peer_key, classical_ct, classical_ctlen))
        goto err_peer;

    /* 2. 使用自己的私钥和对方临时公钥进行 derive */
    UCI_PKEY_CTX *derive_ctx = UCI_PKEY_CTX_new_from_pkey(NULL, ctx->classical_key, NULL);
    if (!UCI_PKEY_derive_init(derive_ctx))
        goto err_peer;

    if (!UCI_PKEY_derive_set_peer(derive_ctx, peer_key))
        goto err_peer;

    size_t classical_sslen = 0;
    if (!UCI_PKEY_derive(derive_ctx, NULL, &classical_sslen))
        goto err_peer;

    unsigned char *classical_ss = malloc(classical_sslen);
    if (!UCI_PKEY_derive(derive_ctx, classical_ss, &classical_sslen))
        goto err_free;

    UCI_PKEY_CTX_free(derive_ctx);
    UCI_PKEY_free(peer_key);

    /* 抗量子 KEM 解封装 */
    UCI_PKEY_CTX *pqc_ctx = UCI_PKEY_CTX_new_from_pkey(NULL, ctx->pqc_key, NULL);
    if (!UCI_PKEY_decapsulate_init(pqc_ctx, NULL))
        goto err_free;

    size_t pqc_sslen = 0;
    if (!UCI_PKEY_decapsulate(pqc_ctx, NULL, &pqc_sslen, pqc_ct, pqc_ctlen))
        goto err_free;

    unsigned char *pqc_ss = malloc(pqc_sslen);
    if (!UCI_PKEY_decapsulate(pqc_ctx, pqc_ss, &pqc_sslen, pqc_ct, pqc_ctlen))
        goto err_free2;

    UCI_PKEY_CTX_free(pqc_ctx);

    /* 组合共享密钥: SHA256(classical_ss || pqc_ss) */
    UCI_MD_CTX *md_ctx = UCI_MD_CTX_new();
    UCI_DigestInit_ex(md_ctx, UCI_sha256(), NULL);
    UCI_DigestUpdate(md_ctx, classical_ss, classical_sslen);
    UCI_DigestUpdate(md_ctx, pqc_ss, pqc_sslen);
    unsigned int final_sslen = 0;
    UCI_DigestFinal_ex(md_ctx, ss, &final_sslen);
    UCI_MD_CTX_free(md_ctx);

    *sslen = final_sslen;

    free(classical_ss);
    free(pqc_ss);
    return 1;

err_free2:
    free(pqc_ss);
err_free:
    free(classical_ss);
err_peer:
    UCI_PKEY_free(peer_key);
err:
    return 0;
}
