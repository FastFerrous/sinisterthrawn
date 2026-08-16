#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "tls.h"
#include "sessions.h"
#include "evt_poll.h"
#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"

/* contains all required underlying mbedtls data structures used throughout connection lifetime -- wrapped for generics with tls.h */
typedef struct mbedtls_conn_t
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context sock;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
} mbedtls_conn_t;

/*
 * upon accepting inbound clients, each session needs to have their own ssl and net context
 * a new tls_conn_t structure will be allocated for each inbound client and this structure will serve as the the opaque `ctx`
 * these structures are only tied to new inbound connections, not to the actual listener's tls_conn_t->ctx structure
 */
typedef struct mbedtls_session_t
{
    mbedtls_ssl_context ssl;
    mbedtls_net_context sock;
} mbedtls_session_t;

/*
 * callback args structure used for use with evt_poll'ing when registering cb, `on_accept`, for handling new clients in SERVER mode
 * mbedtls_conn_t is the listener structure and token is used to supply to the session handler for thread synch
 */
typedef struct mbedtls_listener_ctx_t
{
    mbedtls_conn_t *mbed_tls;
    CancellationToken *token;
} mbedtls_listener_ctx_t;

/* declarations */
static tls_conn_status_t tls_connect(tls_conn_t *conn, stamped_config_t *config);
static tls_conn_status_t tls_listen(tls_conn_t *conn, stamped_config_t *config, CancellationToken *token);
static int mtls_spki_verification(void *cb_cxt, mbedtls_x509_crt *cert, int depth, uint32_t *flags);
static char *decode_str_data(Slice *slice, uint8_t key);
static void handle_inbound_clients(int fd, uint32_t events, void *ctx);
static void destroy_client_session(void *ctx);
static void destroy_tls_conn(void *ctx);

tls_conn_t *tls_new(stamped_config_t *config)
{
    bool status = false;
    tls_conn_t *tls_conn = NULL;
    mbedtls_conn_t *mbed_tls = NULL;

    if (NULL == config)
    {
        goto exit;
    }

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

    /* store underlying mbedtls instance */
    tls_conn->ctx = mbed_tls;

    mbedtls_ssl_init(&mbed_tls->ssl);
    mbedtls_ssl_config_init(&mbed_tls->conf);
    mbedtls_net_init(&mbed_tls->sock);
    mbedtls_x509_crt_init(&mbed_tls->client_cert);
    mbedtls_pk_init(&mbed_tls->client_key);

    /* create shared ssl context between both client and server modes, along with configuration of mTLS */
    int endpoint = (config->mode == CALLBACK)
                       ? MBEDTLS_SSL_IS_CLIENT
                       : MBEDTLS_SSL_IS_SERVER;

    if (mbedtls_ssl_config_defaults(&mbed_tls->conf, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT))
    {
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&mbed_tls->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&mbed_tls->conf, mtls_spki_verification, (void *)&config->spki);

    /* load public and private keys for use during handshake and register within mbedtls */
    if (0 != mbedtls_x509_crt_parse_der(&mbed_tls->client_cert,
                                        config->public_key.data, config->public_key.len))
    {
        goto exit;
    }

    if (0 != mbedtls_pk_parse_key(&mbed_tls->client_key,
                                  config->private_key.data, config->private_key.len,
                                  NULL, 0))
    {
        goto exit;
    }

    if (0 != mbedtls_ssl_conf_own_cert(&mbed_tls->conf,
                                       &mbed_tls->client_cert, &mbed_tls->client_key))
    {
        goto exit;
    }

    if (0 != mbedtls_ssl_setup(&mbed_tls->ssl, &mbed_tls->conf))
    {
        goto exit;
    }

    /* assign callback functions */
    tls_conn->connect = tls_connect;
    tls_conn->listen = tls_listen;
    tls_conn->destroy = destroy_tls_conn;

    status = true;

exit:
    if (!status && tls_conn)
    {
        tls_destroy(&tls_conn);
    }

    return tls_conn;
}

void tls_destroy(tls_conn_t **tls_conn)
{
    if (NULL == tls_conn || NULL == *tls_conn)
    {
        return;
    }

    if ((*tls_conn)->destroy && ((*tls_conn)->ctx))
    {
        ((*tls_conn)->destroy((*tls_conn)->ctx));
        free((*tls_conn)->ctx);
    }

    free(*tls_conn);
    *tls_conn = NULL;
}

static tls_conn_status_t tls_connect(tls_conn_t *conn, stamped_config_t *config)
{
    tls_conn_status_t status = TLS_INVALID_PTR;
    mbedtls_conn_t *mbed_tls = NULL;
    char *address = NULL;
    char *hostname = NULL;
    char port[MAXIMUM_PORT_STR_LEN] = {0};

    if (NULL == conn || NULL == conn->ctx || NULL == config)
    {
        goto exit;
    }

    /* cast opaque pointer to underlying mbedtls structure for setup and configuration */
    mbed_tls = (mbedtls_conn_t *)conn->ctx;

    /* store SNI of remote cert that will be checked against */
    hostname = decode_str_data(&config->sni, config->key);
    if (NULL == hostname)
    {
        status = TLS_INVALID_ARGS;
        goto exit;
    }

    if (mbedtls_ssl_set_hostname(&mbed_tls->ssl, (const char *)hostname))
    {
        status = TLS_INTERNAL_ERR;
        goto exit;
    }

    /* attempt initial connection; on success perform ssl handshake */
    address = decode_str_data(&config->address, config->key);
    if (NULL == address)
    {
        status = TLS_INVALID_ARGS;
        goto exit;
    }

    int result = snprintf(port, MAXIMUM_PORT_STR_LEN, "%u", config->port);
    if (0 > result || result >= MAXIMUM_PORT_STR_LEN)
    {
        status = TLS_INVALID_ARGS;
        goto exit;
    }

    if (0 != mbedtls_net_connect(&mbed_tls->sock, (const char *)address, (const char *)port, MBEDTLS_NET_PROTO_TCP))
    {
        status = TLS_CONNECT_ERR;
        goto exit;
    }

    conn->fd = mbed_tls->sock.fd;

    /* setup callbacks for internal mbedtls write and read operations */
    mbedtls_ssl_set_bio(&mbed_tls->ssl, &mbed_tls->sock,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    if (0 != mbedtls_ssl_handshake(&mbed_tls->ssl))
    {
        status = TLS_HANDSHAKE_ERR;
        goto exit;
    }

    /*
     * currently no post handshake validation of flags as self signed certs will still be flagged for non trusted.
     * once legitimate certs are added, this could be readded; however, the callback is fully functional without this validation as is
     */

    // if (0 != mbedtls_ssl_get_verify_result(&mbed_tls->ssl))
    // {
    //     goto exit;
    // }

    status = TLS_SUCCESS;

exit:
    if (hostname)
    {
        free(hostname);
    }

    if (address)
    {
        free(address);
    }

    return status;
}

static tls_conn_status_t tls_listen(tls_conn_t *conn, stamped_config_t *config, CancellationToken *token)
{
    tls_conn_status_t status = TLS_INVALID_PTR;
    mbedtls_conn_t *mbed_tls = NULL;
    char *address = NULL;
    poll_ctx_t *ctx = NULL;
    char port[MAXIMUM_PORT_STR_LEN] = {0};

    if (NULL == conn || NULL == conn->ctx || NULL == config || NULL == token)
    {
        goto exit;
    }

    if (!token_acquire(token))
    {
        status = TLS_INVALID_ARGS;
        goto exit;
    }

    /* cast opaque pointer to underlying mbedtls structure for setup and configuration */
    mbed_tls = (mbedtls_conn_t *)conn->ctx;

    address = decode_str_data(&config->address, config->key);
    if (NULL == address)
    {
        status = TLS_INVALID_ARGS;
        goto exit;
    }

    int result = snprintf(port, MAXIMUM_PORT_STR_LEN, "%u", config->port);
    if (0 > result || result >= MAXIMUM_PORT_STR_LEN)
    {
        status = TLS_INVALID_ARGS;
        goto exit;
    }

    /* attempt to bind on specified address and port */
    if (0 != mbedtls_net_bind(&mbed_tls->sock, (const char *)address, (const char *)port, MBEDTLS_NET_PROTO_TCP))
    {
        status = TLS_BIND_ERR;
        goto exit;
    }

    /* register socket and await inbound connections as long as the token has not been signaled to shutdown */
    mbedtls_listener_ctx_t listener_ctx = {
        .mbed_tls = mbed_tls,
        .token = token};

    ctx = pollctx_create();
    if (NULL == ctx)
    {
        status = TLS_INTERNAL_ERR;
        goto exit;
    }

    if (EVT_POLL_SUCCESS != pollctx_register(ctx, mbed_tls->sock.fd, EPOLLIN, handle_inbound_clients, &listener_ctx))
    {
        status = TLS_INTERNAL_ERR;
        goto exit;
    }

    while (!token_is_cancelled((const CancellationToken *)token))
    {
        if (EPOLL_GENERIC_ERR == pollctx_dispatch(ctx, SOCKET_TIMEOUT))
        {
            status = TLS_INTERNAL_ERR;
            goto exit;
        }
    }

exit:
    if (ctx)
    {
        pollctx_destroy(&ctx);
    }

    if (address)
    {
        free(address);
    }

    token_release(token);

    return status;
}

/*
 * helper functions for destroying underlying mbedtls contexts
 * these will be assigned within the vtable for the public `tls_destroy`
 * these functions allow clients to only call `tls_destroy` and still remain `unaware` of underlying proto
 */
static void destroy_client_session(void *ctx)
{
    if (NULL == ctx)
    {
        return;
    }

    mbedtls_session_t *session = (mbedtls_session_t *)ctx;

    mbedtls_ssl_free(&session->ssl);
    mbedtls_net_free(&session->sock);

    return;
}

static void destroy_tls_conn(void *ctx)
{
    if (NULL == ctx)
    {
        return;
    }

    mbedtls_conn_t *mbed_tls = (mbedtls_conn_t *)ctx;

    mbedtls_ssl_free(&mbed_tls->ssl);
    mbedtls_ssl_config_free(&mbed_tls->conf);
    mbedtls_net_free(&mbed_tls->sock);
    mbedtls_x509_crt_free(&mbed_tls->client_cert);
    mbedtls_pk_free(&mbed_tls->client_key);

    return;
}

/*
 * callback function supplied to mbedtls to peform validation of the SPKI within the presented public key
 * validation is performed by extracting teh SPKI, hashing it with SHA256 and comparing whether it matches our expected stamped value
 */
static int mtls_spki_verification(void *cb_cxt, mbedtls_x509_crt *cert, int depth, uint32_t *flags)
{
    int result = GENERIC_TLS_FAILURE;

    /* validate supplied callback pointers */
    if (NULL == cb_cxt || NULL == cert || NULL == flags)
    {
        goto exit;
    }

    /* only hashing the spki of the leaf's public key; if not leaf, return 0 and continue to next certificate */
    if (0 != depth)
    {
        result = 0;
        goto exit;
    }

    /* extract spki from public key and hash to compare against supplied pin */
    unsigned char hash[SPKI_HASH_LEN] = {0};
    size_t hash_len = 0;
    if (PSA_SUCCESS != psa_hash_compute(PSA_ALG_SHA_256, cert->pk_raw.p, cert->pk_raw.len, hash, sizeof(hash), &hash_len))
    {
        goto exit;
    }

    if (0 != memcmp(hash, ((Slice *)cb_cxt)->data, SPKI_HASH_LEN))
    {
        *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        goto exit;
    }

    /* SPKI matched, settings flags to 0 allowing the connection to continue */
    *flags = 0;
    result = 0;

exit:
    return result;
}

/*
 * simple helper function to decode the string data that is referenced within the slice
 */
static char *decode_str_data(Slice *slice, uint8_t key)
{
    char *decoded_str = NULL;

    if (NULL == slice)
    {
        goto exit;
    }

    decoded_str = calloc(1, slice->len + 1);
    if (NULL == decoded_str)
    {
        goto exit;
    }

    for (uint64_t i = 0; i < slice->len; i++)
    {
        decoded_str[i] = slice->data[i] ^ key;
    }

exit:
    return decoded_str;
}

/*
 * callback function used to handle inbound clients
 * callback will allocate a new tls_conn_t structure and assign required vtable addresses for session use
 */
static void handle_inbound_clients(int fd, uint32_t events, void *ctx)
{
    bool status = false;
    mbedtls_session_t *client = NULL;
    tls_conn_t *tls_conn = NULL;
    session_ctx_t *session = NULL;

    if (INVALID_EVENTFD_DESCRIPTOR == fd || NULL == ctx)
    {
        goto exit;
    }

    if (!(events & EPOLLIN))
    {
        goto exit;
    }

    /* casting back so that we are able to access the listener socket as well as the cancellation token as new clients will be provided that for synchronization */
    mbedtls_listener_ctx_t *listener_cxt = (mbedtls_listener_ctx_t *)ctx;

    /* allocate client mbedtls structure that will be stored within the generic tls_conn_t for each session */
    client = calloc(1, sizeof(mbedtls_session_t));
    if (NULL == client)
    {
        goto exit;
    }

    mbedtls_ssl_init(&client->ssl);
    mbedtls_net_init(&client->sock);

    /* accept inbound connection and apply ssl configuration to new socket */
    if (0 != mbedtls_net_accept(&listener_cxt->mbed_tls->sock, &client->sock, NULL, 0, NULL))
    {
        goto exit;
    }

    if (0 != mbedtls_ssl_setup(&client->ssl, &listener_cxt->mbed_tls->conf))
    {
        goto exit;
    }

    mbedtls_ssl_set_bio(&client->ssl, &client->sock, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* set send/recv timeouts for client socket operations */
    struct timeval tv = {
        .tv_sec = SOCKET_TIMEOUT,
        .tv_usec = 0};

    if (-1 == setsockopt(client->sock.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)))
    {
        goto exit;
    }

    if (-1 == setsockopt(client->sock.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)))
    {
        goto exit;
    }

    /* attempt to perform ssl handshake */
    int ret = 0;
    time_t start_time = time(NULL);
    while (0 != (ret = mbedtls_ssl_handshake(&client->ssl)))
    {
        if (!(MBEDTLS_ERR_SSL_WANT_READ == ret || MBEDTLS_ERR_SSL_WANT_WRITE == ret))
        {
            goto exit;
        }

        if (SOCKET_TIMEOUT <= difftime(time(NULL), start_time))
        {
            goto exit;
        }
    }

    /* create session structure for client sessions and spawn child thread  */
    tls_conn = calloc(1, sizeof(tls_conn_t));
    if (NULL == tls_conn)
    {
        goto exit;
    }

    session = calloc(1, sizeof(session_ctx_t));
    if (NULL == session)
    {
        goto exit;
    }

    tls_conn->ctx = client;
    tls_conn->fd = client->sock.fd;
    tls_conn->destroy = destroy_client_session;
    // tls_conn->recv = tls_recv();
    // tls_conn->send = tls_send();

    session->conn = tls_conn;
    session->token = listener_cxt->token;

    pthread_t tid = 0;
    if (0 != pthread_create(&tid, NULL, client_session_repl, (void *)session))
    {
        goto exit;
    }

    /*
     * detaching thread as the token will be signaled when the tokens need to be closed
     * when tokens are shared amongst threads, those threads will all `acquire` the token, therefore creating a reference
     * during token destroy within the main thread, it will not terminate the program until the references have dropped to 0 or the timeout has occured
     * indicating a critical error on teardown anyway
     */
    pthread_detach(tid);

    status = true;

exit:
    if (!status && client)
    {
        mbedtls_ssl_free(&client->ssl);
        mbedtls_net_free(&client->sock);
        free(client);
    }

    if (!status && tls_conn)
    {
        free(tls_conn);
    }

    if (!status && session)
    {
        free(session);
    }

    return;
}

// todo: within handle inbound clients callback, handle errors as well, token will need cancelled on critical errors
// todo: once all is done, ensure tests with valgrind are performed along with clang-tidy
