/*
 * Minimal provider skeleton (for onboarding custom SIGN algorithm)
 *
 * NOTE:
 * - This file is a learning scaffold and is NOT wired into CMake by default.
 * - Replace mysigdemo_* callbacks with your real implementation.
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

/* -------- signature callbacks (skeleton) -------- */

typedef struct {
    void *provctx;
} MYSIG_SIG_CTX;

static void *mysig_newctx(void *provctx, const char *propq)
{
    (void)propq;
    MYSIG_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) ctx->provctx = provctx;
    return ctx;
}

static void mysig_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int mysig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    (void)vctx; (void)vkey; (void)params;
    return 1;
}

static int mysig_sign(void *vctx,
                      unsigned char *sig, size_t *siglen, size_t sigsize,
                      const unsigned char *tbs, size_t tbslen)
{
    (void)vctx; (void)tbs; (void)tbslen;
    /* TODO: fill real sign implementation */
    if (sig == NULL) {
        *siglen = 64; /* example size */
        return 1;
    }
    if (sigsize < 64) return 0;
    memset(sig, 0x5A, 64);
    *siglen = 64;
    return 1;
}

static int mysig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    (void)vctx; (void)vkey; (void)params;
    return 1;
}

static int mysig_verify(void *vctx,
                        const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    (void)vctx; (void)tbs; (void)tbslen;
    /* TODO: fill real verify implementation */
    return (sig != NULL && siglen == 64) ? 1 : 0;
}

static const OSSL_DISPATCH mysig_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))mysig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))mysig_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))mysig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))mysig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))mysig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))mysig_verify },
    { 0, NULL }
};

/* -------- query table (skeleton) -------- */

static const OSSL_ALGORITHM my_sigs[] = {
    /* property key MUST match SDF fetch expectations */
    { "mysigdemo", "provider=myoqsprov", mysig_signature_functions },
    { NULL, NULL, NULL }
};

/* Your provider query_operation should return my_sigs for SIGNATURE operation. */
