#ifndef TLS_H
#define TLS_H

#include <stddef.h>
#include "patch.h"

#define INVALID_SOCKFD -1

typedef enum tls_conn_status_t
{
    TLS_SUCCESS,
    TLS_INVALID_PTR,
    TLS_INVALID_PORT
} tls_conn_status_t;

typedef struct tls_conn_t
{
    /* opaque pointer into library specific context ie mbedTLS, openSSL, etc. */
    void *ctx;

    /* underlying fd used within the context; shared for event monitoring, if needed */
    int fd;

    /* tls library vtable */
    tls_conn_status_t (*connect)(struct tls_conn_t *conn, stamped_config_t *config);
    int (*send)(struct tls_conn_t *conn, const unsigned char *buf, size_t len);
    int (*recv)(struct tls_conn_t *conn, unsigned char *buf, size_t len);
    void (*close)(struct tls_conn_t *conn);
} tls_conn_t;

/* opaque function that performs specified tls libraries initialization */
tls_conn_t *tls_new(void);

/* opaque function that performs specified tls libraries cleanup */
void tls_destroy(tls_conn_t **tls_conn);

#endif

// tls_conn_status_t (*connect)(struct tls_conn_t *conn, const char *host, const char *port); -- removed for testing stamped config
