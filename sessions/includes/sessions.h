#ifndef SESSIONS_H
#define SESSIONS_H

#include <stdbool.h>
#include "tls.h"
#include "token.h"
#include "evt_poll.h"

/*
 * stores comms profile + cancellation token for synchronization purposes
 * sessions are "unaware" of the comms profiles, so they wrap the tls_conn_t for generic usage
 * via function tables
 */
typedef struct session_ctx_t
{
    tls_conn_t *conn;

    /* local session status -- non critical errors, ie remote peer disconnection, will set this to gracefully terminate the client session and thread */
    bool is_closed;

    /* application status -- critical error occurred, setting this will begin program termination */
    CancellationToken *token;

    /* event poll for each session, stored within session ctx to permit sessions to dynamically grow as required, ie tunneling */
    poll_ctx_t *poll;
} session_ctx_t;

/* single entry point for handling all client sessions, regardless of being instantiated via CALLBACK or SERVER mode */
void *client_session_repl(void *ctx);

#endif