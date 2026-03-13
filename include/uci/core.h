/*
 * UCI Core Interface
 * Wrapper for OpenSSL core functionality
 */

#ifndef UCI_CORE_H
#define UCI_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include OpenSSL core headers */
#include <openssl/core.h>

/* UCI type aliases for core types */
typedef OSSL_CORE_HANDLE UCI_CORE_HANDLE;
typedef OPENSSL_CORE_CTX UCI_CORE_CTX;
typedef OSSL_CORE_BIO UCI_CORE_BIO;
typedef OSSL_DISPATCH UCI_DISPATCH;
typedef OSSL_ITEM UCI_ITEM;
typedef OSSL_ALGORITHM UCI_ALGORITHM;
typedef OSSL_PARAM UCI_PARAM;
typedef OSSL_CALLBACK UCI_CALLBACK;
typedef OSSL_PASSPHRASE_CALLBACK UCI_PASSPHRASE_CALLBACK;

/* UCI dispatch table macros */
#define UCI_DISPATCH_END OSSL_DISPATCH_END

/* UCI library context type */
typedef OSSL_LIB_CTX UCI_LIB_CTX;

/* UCI parameter data types */
#define UCI_PARAM_INTEGER OSSL_PARAM_INTEGER
#define UCI_PARAM_UNSIGNED_INTEGER OSSL_PARAM_UNSIGNED_INTEGER
#define UCI_PARAM_REAL OSSL_PARAM_REAL
#define UCI_PARAM_UTF8_STRING OSSL_PARAM_UTF8_STRING
#define UCI_PARAM_OCTET_STRING OSSL_PARAM_OCTET_STRING
#define UCI_PARAM_UTF8_PTR OSSL_PARAM_UTF8_PTR
#define UCI_PARAM_OCTET_PTR OSSL_PARAM_OCTET_PTR

#ifdef __cplusplus
}
#endif

#endif /* UCI_CORE_H */
