/*
 * UCI 混合密码服务接口
 * 支持经典算法 + 抗量子算法的混合模式
 */

#ifndef UCI_HYBRID_H
#define UCI_HYBRID_H

#include "uci.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 混合签名上下文 */
typedef struct uci_hybrid_sign_ctx_st UCI_HYBRID_SIGN_CTX;

/* 混合 KEM 上下文 */
typedef struct uci_hybrid_kem_ctx_st UCI_HYBRID_KEM_CTX;

/* 混合签名接口 */
UCI_HYBRID_SIGN_CTX *UCI_HYBRID_SIGN_CTX_new(void);
void UCI_HYBRID_SIGN_CTX_free(UCI_HYBRID_SIGN_CTX *ctx);

int UCI_HYBRID_SIGN_init(UCI_HYBRID_SIGN_CTX *ctx,
                         UCI_PKEY *classical_key,
                         UCI_PKEY *pqc_key);

int UCI_HYBRID_sign(UCI_HYBRID_SIGN_CTX *ctx,
                    unsigned char *sig, size_t *siglen,
                    const unsigned char *msg, size_t msglen);

int UCI_HYBRID_verify(UCI_HYBRID_SIGN_CTX *ctx,
                      const unsigned char *sig, size_t siglen,
                      const unsigned char *msg, size_t msglen);

/* 混合 KEM 接口 */
UCI_HYBRID_KEM_CTX *UCI_HYBRID_KEM_CTX_new(void);
void UCI_HYBRID_KEM_CTX_free(UCI_HYBRID_KEM_CTX *ctx);

int UCI_HYBRID_KEM_init(UCI_HYBRID_KEM_CTX *ctx,
                        UCI_PKEY *classical_key,
                        UCI_PKEY *pqc_key);

int UCI_HYBRID_encapsulate(UCI_HYBRID_KEM_CTX *ctx,
                           unsigned char *ct, size_t *ctlen,
                           unsigned char *ss, size_t *sslen);

int UCI_HYBRID_decapsulate(UCI_HYBRID_KEM_CTX *ctx,
                           unsigned char *ss, size_t *sslen,
                           const unsigned char *ct, size_t ctlen);

#ifdef __cplusplus
}
#endif

#endif /* UCI_HYBRID_H */
