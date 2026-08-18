#ifndef SESSIONS_H
#define SESSIONS_H

#include <stdbool.h>
#include "tls.h"
#include "token.h"

/*
 * stores comms profile + cancellation token for synchronization purposes
 * sessions are "unaware" of the comms profiles, so they wrap the tls_conn_t for generic usage
 * via function tables
 */
typedef struct session_ctx_t
{
    bool is_closed;
    tls_conn_t *conn;
    CancellationToken *token;
} session_ctx_t;

/* single entry point for handling all client sessions, regardless of being instantiated via CALLBACK or SERVER mode */
void *client_session_repl(void *ctx);

#endif