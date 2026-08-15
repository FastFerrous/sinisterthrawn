#ifndef TOKEN_H
#define TOKEN_H

#include <stdbool.h>

#define INVALID_EVENTFD_DESCRIPTOR -1

/*
 * Cancellation token is similar to CancellationToken in Rust API, however we have no native clone() in C
 * This library requires that any thread or poller that wants to have a `copy` of the token, must call acquire/release to track the reference counter
 * When the owner calls into `token_destroy`, that function will block until reference count has dropped to 0, therefore it is on the programmer to ensure that this is followed
 */

typedef struct CancellationToken CancellationToken;

/* Initializes a new cancellation token */
CancellationToken *token_create();

/* Checks whether underlying atomic has been set */
bool token_is_cancelled(const CancellationToken *token);

/* Exposes eventfd for epoll, select, etc. */
int token_get_event(const CancellationToken *token);

/* Sets atomic and writes to eventfd for potential `pollers` */
bool token_shutdown(CancellationToken *token);

/* Assuming the token has not been shutdown, increments internal reference counter */
bool token_acquire(CancellationToken *token);

/* Assuming the token has been acquired before and non zero reference counter, decrements counter */
bool token_release(CancellationToken *token);

/* performs `token_shutdown` if not already shutdown and then frees token structure */
bool token_destroy(CancellationToken **token);

#endif
