#ifndef EVT_POLL_H
#define EVT_POLL_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/epoll.h>

#define EPOLL_INDEFINITE -1
#define EPOLL_GENERIC_ERR -1
#define INITIAL_POLL_EVENTS 8
#define DOUBLE_POLL_EVENTS 2
#define MAX_POLL_EVENTS 128

typedef enum poll_status_t
{
    EVT_POLL_SUCCESS,
    EVT_POLL_ALLOC_ERR,
    EVT_POLL_INVALID_ARGS,
    EVT_POLL_DUPLICATE_FD,
    EVT_POLL_INVALID_FD,
    EVT_POLL_MAX_CAPACITY,
    EVT_POLL_UNABLE_TO_REGISTER,
    EVT_POLL_UNABLE_TO_REMOVE,
} poll_status_t;

/* opaque pointer storing internal epoll_fd */
typedef struct poll_ctx_t poll_ctx_t;

/* signature used for callback functions that will be triggered on events */
typedef void (*poll_callback_t)(int fd, uint32_t events, void *user_data);

/* creates a new polling context storing underlying epoll_fd */
poll_ctx_t *pollctx_create(void);

/* registers a file descriptor with the specified events and correlates a callback function to be used after event has fired */
poll_status_t pollctx_register(poll_ctx_t *ctx, int fd, uint32_t events, poll_callback_t cb, void *cb_data);

/* removes fd from poll context */
poll_status_t pollctx_remove(poll_ctx_t *ctx, int fd);

/* blocking call that will perform epoll wait until timeout_ms has elapsed or an error occured */
int pollctx_dispatch(poll_ctx_t *ctx, int timeout_ms);

/* destroys poll context, closing internal epoll fd */
void pollctx_destroy(poll_ctx_t **ctx);

#endif
