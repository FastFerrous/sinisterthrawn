#ifndef TLS_H
#define TLS_H

#include <stddef.h>
#include "patch.h"
#include "token.h"

#define INVALID_SOCKFD -1
#define GENERIC_TLS_FAILURE -1
#define MAXIMUM_PORT_STR_LEN 6
#define SOCKET_TIMEOUT 5000
#define MAXIMUM_PACKET_LEN 16384

typedef enum tls_conn_status_t
{
    /*
     * most return values will have mappings from generic <-> underlying library
     * however, in case of library specific errors that are non generic, the `TLS_INTERNAL_ERR` will be used
     */

    TLS_SUCCESS,
    TLS_INVALID_PTR,
    TLS_INVALID_ARGS,
    TLS_HANDSHAKE_ERR,
    TLS_CONNECT_ERR,
    TLS_BIND_ERR,
    TLS_READ_ERR,
    TLS_WRITE_ERR,
    TLS_INTERNAL_ERR,
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
    tls_conn_status_t (*send)(struct tls_conn_t *conn, unsigned char *buf, size_t len);
    tls_conn_status_t (*recv)(struct tls_conn_t *conn, unsigned char *buf, size_t len);
    void (*destroy)(void *ctx);
} tls_conn_t;

/* opaque function that performs specified tls libraries initialization */
tls_conn_t *tls_new(stamped_config_t *config);

/* opaque function that performs specified tls libraries cleanup */
void tls_destroy(tls_conn_t **tls_conn);

#endif

// todo: remove the maximum packet len once all integrated