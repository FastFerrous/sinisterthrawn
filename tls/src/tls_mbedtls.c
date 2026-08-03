#include <stdlib.h>
#include <stdbool.h>
#include "tls.h"
#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

typedef struct mbedtls_conn_t
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context sock;
} mbedtls_conn_t;

/* declarations */
static tls_conn_status_t tls_connect(tls_conn_t *conn, const char *host, const char *port);

void tls_destroy(tls_conn_t **tls_conn)
{
    if (NULL == tls_conn || NULL == *tls_conn)
    {
        return;
    }

    if ((*tls_conn)->ctx)
    {
        mbedtls_conn_t *mbed_tls = (mbedtls_conn_t *)(*tls_conn)->ctx;

        mbedtls_ssl_free(&mbed_tls->ssl);
        mbedtls_ssl_config_free(&mbed_tls->conf);
        mbedtls_net_free(&mbed_tls->sock);

        free(mbed_tls);
    }

    free(*tls_conn);
    *tls_conn = NULL;
}

tls_conn_t *tls_new(void)
{
    bool status = false;
    tls_conn_t *tls_conn = NULL;
    mbedtls_conn_t *mbed_tls = NULL;

    /* initialize mbedtls crypto -- required before any mbedtls calls */
    if (PSA_SUCCESS != psa_crypto_init())
    {
        goto exit;
    }

    /* allocate and initialize tls connection structure and underlying library state */
    tls_conn = calloc(1, sizeof(tls_conn_t));
    if (NULL == tls_conn)
    {
        goto exit;
    }

    tls_conn->fd = INVALID_SOCKFD;

    mbed_tls = calloc(1, sizeof(mbedtls_conn_t));
    if (NULL == mbed_tls)
    {
        goto exit;
    }

    mbedtls_ssl_init(&mbed_tls->ssl);
    mbedtls_ssl_config_init(&mbed_tls->conf);
    mbedtls_net_init(&mbed_tls->sock);

    /* store mbedtls instance and assign callback functions */
    tls_conn->ctx = mbed_tls;
    tls_conn->connect = tls_connect;

    status = true;

exit:
    if (!status && tls_conn)
    {
        tls_destroy(&tls_conn);
    }

    return tls_conn;
}

static tls_conn_status_t tls_connect(tls_conn_t *conn, const char *host, const char *port)
{
    tls_conn_status_t status = TLS_INVALID_PTR;
    mbedtls_conn_t *mbed_tls = NULL;

    if (NULL == conn || NULL == conn->ctx || NULL == host || NULL == port)
    {
        goto exit;
    }

    /* cast opaque pointer to underlying mbedtls structure for setup and configuration */
    mbed_tls = (mbedtls_conn_t *)conn->ctx;

    /* configure mbedtls client configuration to enforce mTLS with provided spki validation callback  */
    if (mbedtls_ssl_config_defaults(&mbed_tls->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT))
    {
        goto exit;
    }

    // mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    // mbedtls_ssl_conf_verify(&s->conf, mtls_spki_verify, NULL);

    if (mbedtls_ssl_setup(&mbed_tls->ssl, &mbed_tls->conf))
    {
        goto exit;
    }

    /* store SNI of remote cert that will be checked against */
    if (mbedtls_ssl_set_hostname(&mbed_tls->ssl, host))
    {
        goto exit;
    }

    // debug
    mbedtls_ssl_conf_authmode(&mbed_tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    // end debug

    /* attempt initial connection; on success perform ssl handshake */
    if (mbedtls_net_connect(&mbed_tls->sock, host, port, MBEDTLS_NET_PROTO_TCP))
    {
        goto exit;
    }

    conn->fd = mbed_tls->sock.fd;

    /* setup callbacks for internal mbedtls write and read operations */
    mbedtls_ssl_set_bio(&mbed_tls->ssl, &mbed_tls->sock,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    if (mbedtls_ssl_handshake(&mbed_tls->ssl))
    {
        goto exit;
    }

    status = TLS_SUCCESS;

exit:
    return status;
}

// todo: add actual client certs to be used via der format and crt_init and crt_parse
// todo: add required errors and implement into code ie connection failure, etc.
