/*
 * UCI Unified Interface Layer
 *
 * Unified API names do not contain algorithm names.
 * Algorithm selection is provided via request parameters.
 */

#ifndef UCI_UNIFIED_H
#define UCI_UNIFIED_H

#include "uci.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UCI_OPERATION_DIGEST = 1,
    UCI_OPERATION_SIGN = 2,
    UCI_OPERATION_VERIFY = 3,
    UCI_OPERATION_KEM_ENCAPSULATE = 4,
    UCI_OPERATION_KEM_DECAPSULATE = 5
} UCI_OPERATION;

typedef struct {
    UCI_OPERATION operation;

    /* Routing / selection parameters */
    UCI_LIB_CTX *libctx;
    const char *algorithm;   /* digest name for digest/sign/verify, e.g. "SHA256" */
    const char *properties;  /* provider/property query string */

    /* Key input for sign/verify/kem */
    UCI_PKEY *key;

    /* Primary input payload */
    const unsigned char *input;
    size_t input_len;

    /* Extra input payload */
    const unsigned char *extra_input;
    size_t extra_input_len;

    /* Primary output payload */
    unsigned char *output;
    size_t *output_len;

    /* Extra output payload */
    unsigned char *extra_output;
    size_t *extra_output_len;

    /* VERIFY result: 1 valid, 0 invalid */
    int verify_ok;
} UCI_UNIFIED_REQUEST;

/* Generic key generation. Algorithm is selected by name parameter. */
int UCI_KeyGenerate(UCI_LIB_CTX *libctx, const char *algorithm,
                    const char *properties, UCI_PKEY **out_key);

/* Uniform public-key blob: DER SubjectPublicKeyInfo */
int UCI_PublicKeyExport(UCI_PKEY *pkey, unsigned char *der, size_t *der_len);
int UCI_PublicKeyImport(UCI_LIB_CTX *libctx, const char *properties,
                        const unsigned char *der, size_t der_len,
                        UCI_PKEY **out_key);

/* Unified operation execution API */
int UCI_Execute(UCI_UNIFIED_REQUEST *req);

#ifdef __cplusplus
}
#endif

#endif /* UCI_UNIFIED_H */
