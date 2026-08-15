#ifndef TLS_H
#define TLS_H

#include <stddef.h>
#include "patch.h"
#include "token.h"

#define INVALID_SOCKFD -1
#define GENERIC_TLS_FAILURE -1
#define MAXIMUM_PORT_STR_LEN 6
#define SOCKET_TIMEOUT 3000 /* 3 seconds */

typedef enum tls_conn_status_t
{
    TLS_SUCCESS,
    TLS_INVALID_PTR,
    TLS_INVALID_PORT
} tls_conn_status_t;

typedef struct tls_conn_t
{
    /* opaque pointer into library specific contexts ie mbedTLS, openSSL, etc. */
    void *ctx;

    /* underlying fd used within the context; shared for event monitoring, if needed */
    int fd;

    /* tls library vtable */
    tls_conn_status_t (*connect)(struct tls_conn_t *conn, stamped_config_t *config);
    tls_conn_status_t (*listen)(struct tls_conn_t *conn, stamped_config_t *config, CancellationToken *token);
    int (*send)(struct tls_conn_t *conn, const unsigned char *buf, size_t len);
    int (*recv)(struct tls_conn_t *conn, unsigned char *buf, size_t len);
    // void (*destroy)(struct tls_conn_t *conn);
} tls_conn_t;

/* opaque function that performs specified tls libraries initialization */
tls_conn_t *tls_new(stamped_config_t *config);

/* opaque function that performs specified tls libraries cleanup */
void tls_destroy(tls_conn_t **tls_conn);

#endif
