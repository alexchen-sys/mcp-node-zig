/* OS mutex bindings for mbedTLS's MBEDTLS_THREADING_ALT (no crypto here):
 * CRITICAL_SECTION on Windows, pthread elsewhere. Installed once at hub
 * startup via mcp_hub_mbedtls_threading_install(), before psa_crypto_init(),
 * so PSA's global state (key store, RNG) is safe under concurrent links. */
#include "mbedtls/threading.h"

#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)

static void mcp_hub_mutex_init(mbedtls_threading_mutex_t *m)
{
    m->state = 0;
#if defined(_WIN32)
    InitializeCriticalSection(&m->cs);
#else
    if (pthread_mutex_init(&m->mutex, NULL) != 0)
        return;
#endif
    m->state = 1;
}

static void mcp_hub_mutex_free(mbedtls_threading_mutex_t *m)
{
    if (m == NULL || m->state == 0)
        return;
#if defined(_WIN32)
    DeleteCriticalSection(&m->cs);
#else
    pthread_mutex_destroy(&m->mutex);
#endif
    m->state = 0;
}

static int mcp_hub_mutex_lock(mbedtls_threading_mutex_t *m)
{
    if (m == NULL || m->state == 0)
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
#if defined(_WIN32)
    EnterCriticalSection(&m->cs);
    return 0;
#else
    if (pthread_mutex_lock(&m->mutex) != 0)
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    return 0;
#endif
}

static int mcp_hub_mutex_unlock(mbedtls_threading_mutex_t *m)
{
    if (m == NULL || m->state == 0)
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
#if defined(_WIN32)
    LeaveCriticalSection(&m->cs);
    return 0;
#else
    if (pthread_mutex_unlock(&m->mutex) != 0)
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    return 0;
#endif
}

void mcp_hub_mbedtls_threading_install(void)
{
    mbedtls_threading_set_alt(mcp_hub_mutex_init, mcp_hub_mutex_free,
                              mcp_hub_mutex_lock, mcp_hub_mutex_unlock);
}

#endif /* MBEDTLS_THREADING_C && MBEDTLS_THREADING_ALT */
