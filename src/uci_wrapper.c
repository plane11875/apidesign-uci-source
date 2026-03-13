/*
 * UCI (Unified Cryptographic Interface) - Provider/Utility helpers
 */

#include <stdarg.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include "uci/uci.h"

UCI_PROVIDER *UCI_PROVIDER_load(UCI_LIB_CTX *libctx, const char *name) {
    const char *pathlist = getenv("OPENSSL_MODULES");
    UCI_PROVIDER *prov = NULL;

    if (pathlist != NULL && strchr(pathlist, ':') != NULL) {
        char *dirs = OPENSSL_strdup(pathlist);
        char *save = NULL;

        for (char *dir = strtok_r(dirs, ":", &save);
             dir != NULL && prov == NULL;
             dir = strtok_r(NULL, ":", &save)) {
            if (OSSL_PROVIDER_set_default_search_path(libctx, dir))
                prov = OSSL_PROVIDER_load(libctx, name);
        }
        OPENSSL_free(dirs);
        return prov;
    }

    return OSSL_PROVIDER_load(libctx, name);
}

int UCI_PROVIDER_unload(UCI_PROVIDER *prov) {
    return OSSL_PROVIDER_unload(prov);
}

int UCI_PROVIDER_available(UCI_LIB_CTX *libctx, const char *name) {
    return OSSL_PROVIDER_available(libctx, name);
}

UCI_PKEY *UCI_PKEY_Q_keygen(UCI_LIB_CTX *libctx, const char *propq,
                            const char *type, ...) {
    va_list args;
    UCI_PKEY *ret = NULL;

    if (type == NULL)
        return EVP_PKEY_Q_keygen(libctx, propq, type);

    va_start(args, type);
    if (OPENSSL_strcasecmp(type, "RSA") == 0) {
        size_t bits = va_arg(args, size_t);
        ret = EVP_PKEY_Q_keygen(libctx, propq, type, bits);
    } else if (OPENSSL_strcasecmp(type, "EC") == 0) {
        char *curve = va_arg(args, char *);
        ret = EVP_PKEY_Q_keygen(libctx, propq, type, curve);
    } else {
        ret = EVP_PKEY_Q_keygen(libctx, propq, type);
    }
    va_end(args);
    return ret;
}
