/*
 * UCI (Unified Cryptographic Interface)
 * 统一密码服务接口 - 最小可行版本
 */

#ifndef UCI_H
#define UCI_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 类型定义 - 映射 OpenSSL 类型，方便上层继续使用 UCI_* 命名 */
typedef EVP_MD UCI_MD;
typedef EVP_MD_CTX UCI_MD_CTX;
typedef EVP_CIPHER UCI_CIPHER;
typedef EVP_CIPHER_CTX UCI_CIPHER_CTX;
typedef EVP_PKEY UCI_PKEY;
typedef EVP_PKEY_CTX UCI_PKEY_CTX;
typedef EVP_MAC UCI_MAC;
typedef EVP_MAC_CTX UCI_MAC_CTX;
typedef EVP_KDF UCI_KDF;
typedef EVP_KDF_CTX UCI_KDF_CTX;
typedef EVP_RAND UCI_RAND;
typedef EVP_RAND_CTX UCI_RAND_CTX;
typedef EVP_ENCODE_CTX UCI_ENCODE_CTX;
typedef OSSL_LIB_CTX UCI_LIB_CTX;
typedef OSSL_PROVIDER UCI_PROVIDER;

/* Provider 管理接口 */
UCI_PROVIDER *UCI_PROVIDER_load(UCI_LIB_CTX *libctx, const char *name);
int UCI_PROVIDER_unload(UCI_PROVIDER *prov);
int UCI_PROVIDER_available(UCI_LIB_CTX *libctx, const char *name);

/* 自动生成的 UCI_* API，覆盖 OpenSSL 的所有 EVP 接口 */
#include "uci_evp_autogen.h"

/* 特殊接口：varargs 版本需要手动封装 */
UCI_PKEY *UCI_PKEY_Q_keygen(UCI_LIB_CTX *libctx, const char *propq,
                            const char *type, ...);

#ifdef __cplusplus
}
#endif

#endif /* UCI_H */
