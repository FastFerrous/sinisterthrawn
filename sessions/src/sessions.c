#include <stdlib.h>
#include "sessions.h"
#include "evt_poll.h"
#include "box.h"

#include <stdio.h> // debug

/* static declarations */
static void token_shutdown_cb(int fd, uint32_t events, void *user_data);
static void handle_client_request(int fd, uint32_t events, void *user_data);

void *client_session_repl(void *ctx)
{
    session_ctx_t *session = NULL;
    poll_ctx_t *poll = NULL;

    if (NULL == ctx)
    {
        goto exit;
    }

    /* cast to session structure to expose tls profile along with cancellation token for evt_poll registration */
    session = (session_ctx_t *)ctx;

    /* increment ref count within token -- basically emulating a 'clone' from rust */
    if (!token_acquire(session->token))
    {
        goto exit;
    }

    /* register poll and correlating eventfd + socket for callback handling */
    poll = pollctx_create();
    if (NULL == poll)
    {
        goto exit;
    }

    if (EVT_POLL_SUCCESS != pollctx_register(poll, session->conn->fd, EPOLLIN, handle_client_request, session))
    {
        goto exit;
    }

    if (EVT_POLL_SUCCESS != pollctx_register(poll, token_get_event(session->token), EPOLLIN, token_shutdown_cb, NULL))
    {
        goto exit;
    }

    while (!token_is_cancelled(session->token) && !session->is_closed)
    {
        if (EPOLL_GENERIC_ERR == pollctx_dispatch(poll, EPOLL_INDEFINITE))
        {
            break;
        }
    }

exit:
    if (poll)
    {
        pollctx_destroy(&poll);
    }

    if (session)
    {
        token_release(session->token);
        tls_destroy(&session->conn);
        free(session);
    }

    return NULL;
}

/*
 * no op function to satisfy callback requirement for evt_poll

 * used to immediately wake up on shutdown signal to avoid awkward timeouts
 * between performing an action and checking the token
 */
static void token_shutdown_cb(int fd, uint32_t events, void *user_data)
{
    return;
}

static void handle_client_request(int fd, uint32_t events, void *user_data)
{
    bool is_critical = false; /* boolean is set when a critical application occurs and the token will need to be set to gracefully tear down */
    box_t *pkt = NULL;
    session_ctx_t *cxt = NULL;

    if (NULL == user_data || INVALID_SOCKFD == fd)
    {
        goto exit;
    }

    /* cast user data back into the client session context */
    cxt = (session_ctx_t *)user_data;

    /* todo: allocate a single box to store read in data from remote peer ( this is just debug , will do header + packet )*/
    pkt = box_new(1, MAXIMUM_PACKET_LEN);
    if (NULL == pkt)
    {
        is_critical = true;
        goto exit;
    }

    if (TLS_SUCCESS != cxt->conn->recv(cxt->conn, box_data((const box_t *)pkt), box_size((const box_t *)pkt)))
    {
        cxt->is_closed = true;
        goto exit;
    }

exit:
    if (pkt)
    {
        box_free(&pkt);
    }

    if (is_critical)
    {
        token_shutdown(cxt->token);
    }

    return;
}

// modify box to include capacity + len, or just track sep
// currently just a quick skeleton, will finish teh comms profile stuff before going any further on client repl