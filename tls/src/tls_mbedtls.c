#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "tls.h"
#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

typedef struct mbedtls_conn_t
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context sock;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
} mbedtls_conn_t;

/* declarations */
static tls_conn_status_t tls_connect(tls_conn_t *conn, stamped_config_t *config);
static int mtls_spki_verification(void *cb_cxt, mbedtls_x509_crt *cert, int depth, uint32_t *flags);

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
        mbedtls_x509_crt_free(&mbed_tls->client_cert);
        mbedtls_pk_free(&mbed_tls->client_key);

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
    mbedtls_x509_crt_init(&mbed_tls->client_cert);
    mbedtls_pk_init(&mbed_tls->client_key);

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

static tls_conn_status_t tls_connect(tls_conn_t *conn, stamped_config_t *config)
{
    tls_conn_status_t status = TLS_INVALID_PTR;
    mbedtls_conn_t *mbed_tls = NULL;

    if (NULL == conn || NULL == conn->ctx || NULL == config)
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

    mbedtls_ssl_conf_authmode(&mbed_tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_set_verify(&mbed_tls->ssl, mtls_spki_verification, (void *)&config->spki);

    /* load client certificates */
    printf("Loading certs\n");

    int ret = mbedtls_x509_crt_parse_der(&mbed_tls->client_cert,
                                         config->public_key.data, config->public_key.len);

    if (0 != ret)
    {
        printf("failed to load public certificate: -0x%04X\n", (unsigned int)-ret);
        printf("cert len: %zu\n", config->public_key.len);
        printf("first bytes: %02X %02X %02X %02X\n",
               config->public_key.data[0], config->public_key.data[1],
               config->public_key.data[2], config->public_key.data[3]);
        goto exit;
    }

    printf("parsed client cert\n");

    if (mbedtls_pk_parse_key(&mbed_tls->client_key,
                             config->private_key.data, config->private_key.len,
                             NULL, 0))
    {
        goto exit;
    }

    printf("parsed private key\n");

    if (mbedtls_ssl_conf_own_cert(&mbed_tls->conf,
                                  &mbed_tls->client_cert, &mbed_tls->client_key))
    {
        goto exit;
    }

    printf("set certs within ssl cxt\n");

    if (mbedtls_ssl_setup(&mbed_tls->ssl, &mbed_tls->conf))
    {
        goto exit;
    }

    /* store SNI of remote cert that will be checked against */
    char hostname[MAX_ADDR_LEN + 1] = {0};
    memcpy(hostname, &config->sni, config->sni.len);

    if (mbedtls_ssl_set_hostname(&mbed_tls->ssl, hostname))
    {
        goto exit;
    }

    /* attempt initial connection; on success perform ssl handshake */
    char address[MAX_ADDR_LEN + 1] = {0};
    memcpy(address, &config->address, config->address.len);

    printf("Attempting to connect");

    if (mbedtls_net_connect(&mbed_tls->sock, address, "4443", MBEDTLS_NET_PROTO_TCP))
    {
        goto exit;
    }

    printf("Connected!");

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

static int mtls_spki_verification(void *cb_cxt, mbedtls_x509_crt *cert, int depth, uint32_t *flags)
{
    *flags = 0;
    return 0;
}

// issues with cert parsing for now, no time to debug. just setting note ( unkown oid, most likely tied to cert algo. need to check this)
// failed to load public certificate: -0x2100
// swapped to prime 256 p256 and now we are attempint to connect. check why failing.

// todo: currently nothing is xord, but it will be so we need to decode the stuff. for now, just testing without obfuscation
// todo: for now storing everything in connect, but whatever can be shared between listener and connect, will most likely need moved into tls_new()
// todo: add required errors and implement into code ie connection failure, etc.
