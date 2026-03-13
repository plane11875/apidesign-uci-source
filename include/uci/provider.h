/*
 * UCI Provider Interface
 * Wrapper for OpenSSL provider functionality
 */

#ifndef UCI_PROVIDER_H
#define UCI_PROVIDER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Include OpenSSL provider headers */
#include <openssl/provider.h>

/* UCI type aliases for provider types */
typedef OSSL_PROVIDER UCI_PROVIDER;
typedef OSSL_ALGORITHM UCI_ALGORITHM;

/*
 * Some OpenSSL builds omit the default search path helpers even though the
 * headers expose them.  Use weak references when the compiler supports it so
 * we can gracefully fall back to a no-op instead of failing to link.
 */
#if defined(__GNUC__) || defined(__clang__)
extern int OSSL_PROVIDER_set_default_search_path(OSSL_LIB_CTX *, const char *)
    __attribute__((weak));
extern const char *OSSL_PROVIDER_get0_default_search_path(OSSL_LIB_CTX *)
    __attribute__((weak));

static inline int UCI_PROVIDER_set_default_search_path(OSSL_LIB_CTX *libctx,
                                                       const char *path)
{
    if (OSSL_PROVIDER_set_default_search_path != NULL)
        return OSSL_PROVIDER_set_default_search_path(libctx, path);
    return 0;
}

static inline const char *UCI_PROVIDER_get0_default_search_path(OSSL_LIB_CTX *libctx)
{
    if (OSSL_PROVIDER_get0_default_search_path != NULL)
        return OSSL_PROVIDER_get0_default_search_path(libctx);
    return NULL;
}
#else
#define UCI_PROVIDER_set_default_search_path OSSL_PROVIDER_set_default_search_path
#define UCI_PROVIDER_get0_default_search_path OSSL_PROVIDER_get0_default_search_path
#endif

/* UCI provider management functions */
#define UCI_PROVIDER_load OSSL_PROVIDER_load
#define UCI_PROVIDER_load_ex OSSL_PROVIDER_load_ex
#define UCI_PROVIDER_try_load OSSL_PROVIDER_try_load
#define UCI_PROVIDER_try_load_ex OSSL_PROVIDER_try_load_ex
#define UCI_PROVIDER_unload OSSL_PROVIDER_unload
#define UCI_PROVIDER_available OSSL_PROVIDER_available
#define UCI_PROVIDER_do_all OSSL_PROVIDER_do_all
#define UCI_PROVIDER_gettable_params OSSL_PROVIDER_gettable_params
#define UCI_PROVIDER_get_params OSSL_PROVIDER_get_params
#define UCI_PROVIDER_self_test OSSL_PROVIDER_self_test
#define UCI_PROVIDER_get_capabilities OSSL_PROVIDER_get_capabilities
#define UCI_PROVIDER_add_conf_parameter OSSL_PROVIDER_add_conf_parameter
#define UCI_PROVIDER_get_conf_parameters OSSL_PROVIDER_get_conf_parameters
#define UCI_PROVIDER_conf_get_bool OSSL_PROVIDER_conf_get_bool
#define UCI_PROVIDER_query_operation OSSL_PROVIDER_query_operation
#define UCI_PROVIDER_unquery_operation OSSL_PROVIDER_unquery_operation
#define UCI_PROVIDER_get0_provider_ctx OSSL_PROVIDER_get0_provider_ctx
#define UCI_PROVIDER_get0_dispatch OSSL_PROVIDER_get0_dispatch
#define UCI_PROVIDER_add_builtin OSSL_PROVIDER_add_builtin
#define UCI_PROVIDER_get0_name OSSL_PROVIDER_get0_name

#ifdef __cplusplus
}
#endif

#endif /* UCI_PROVIDER_H */
