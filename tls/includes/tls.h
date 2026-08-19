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

// each protocol needs to handle packet flow ie hdr + data + padding. when a request comes in to send + recv, comms will handle the padding, etc. application needs a limit to data size and then a % is added as padding from comms. Comms will add/strip and application is none the wiser. only legit data is returned to application
// for above: hdr will be defined here so comms can share it

// for the shared header, etc. we will be doing padding to ensure that we have wire variation. max packet is the above define. max data len is 8192. so the other half is reserved for padding. add that as well. application is responsible for ensuring that data does not exceed the 8192 amount. or, we just send the data to the comms and comms can manage that
// most likely will have a proto.h and proto.c thats used by the tls libraries for a shared common state with packets, etc. -- should only need to write once and then can be called by the correlating tls library, ie get padding, strip padding, etc.