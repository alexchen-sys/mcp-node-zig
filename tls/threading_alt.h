/* Mutex type for MBEDTLS_THREADING_ALT: the OS primitive plus a state byte
 * mirroring mbedTLS's own pthread flavor, so a failed init leaves the mutex
 * in a state where lock reliably errors and free is a no-op. */
#ifndef MCP_HUB_THREADING_ALT_H
#define MCP_HUB_THREADING_ALT_H

#if defined(_WIN32)
#include <windows.h>
typedef struct mbedtls_threading_mutex_t {
    CRITICAL_SECTION cs;
    char state;
} mbedtls_threading_mutex_t;
#else
#include <pthread.h>
typedef struct mbedtls_threading_mutex_t {
    pthread_mutex_t mutex;
    char state;
} mbedtls_threading_mutex_t;
#endif

#endif /* MCP_HUB_THREADING_ALT_H */
