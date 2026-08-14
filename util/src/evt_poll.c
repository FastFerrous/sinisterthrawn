#include <stdlib.h>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include "evt_poll.h"

typedef struct poll_ctx_t
{
    int epoll_fd;
    poll_entry_t **entries;
    uint8_t count;
    uint8_t capacity;
} poll_ctx_t;

typedef struct poll_entry_t
{
    int fd;
    poll_callback_t cb;
    void *cb_data;
} poll_entry_t;

/*
 * searches for supplied fd within epoll poll_ctx structure
 * returns true and the correlating index on success or false if not found
 */
static bool pollctx_find(poll_ctx_t *ctx, int fd, uint8_t *index);

poll_ctx_t *pollctx_create(void)
{
    bool status = false;

    poll_ctx_t *ctx = calloc(1, sizeof(poll_ctx_t));
    if (NULL == ctx)
    {
        goto exit;
    }

    ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (EPOLL_GENERIC_ERR == ctx->epoll_fd)
    {
        goto exit;
    }

    ctx->entries = calloc(INITIAL_POLL_EVENTS, sizeof(poll_entry_t *));
    if (NULL == ctx->entries)
    {
        goto exit;
    }

    ctx->capacity = INITIAL_POLL_EVENTS;
    ctx->count = 0;

    status = true;

exit:
    if (!status && ctx)
    {
        if (EPOLL_GENERIC_ERR != ctx->epoll_fd)
        {
            close(ctx->epoll_fd);
        }

        if (ctx->entries)
        {
            free(ctx->entries);
        }

        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

poll_status_t pollctx_register(poll_ctx_t *ctx, int fd, uint32_t events, poll_callback_t cb, void *cb_data)
{
    poll_status_t status = EVT_POLL_INVALID_ARGS;
    poll_entry_t *entry = NULL;

    if (NULL == ctx || 0 > fd || NULL == cb)
    {
        goto exit;
    }

    /* check whether the supplied fd has already been registered */
    uint8_t index = 0;
    if (pollctx_find(ctx, fd, &index))
    {
        status = EVT_POLL_DUPLICATE_FD;
        goto exit;
    }

    /* check whether adding one additional fd would meet capacity, if so, realloc */
    if (ctx->capacity == ctx->count)
    {
        if (MAX_POLL_EVENTS < ctx->capacity * DOUBLE_POLL_EVENTS)
        {
            status = EVT_POLL_MAX_CAPACITY;
            goto exit;
        }

        uint8_t new_capacity = ctx->capacity * DOUBLE_POLL_EVENTS;
        poll_entry_t **tmp = realloc(ctx->entries, new_capacity * sizeof(poll_entry_t *));
        if (NULL == tmp)
        {
            status = EVT_POLL_ALLOC_ERR;
            goto exit;
        }

        memset(tmp + ctx->capacity, 0, (new_capacity - ctx->capacity) * sizeof(poll_entry_t *));

        ctx->entries = tmp;
        ctx->capacity = new_capacity;
    }

    /* allocate custom structure to store callback and supplied callback data within epoll_event */
    entry = calloc(1, sizeof(poll_entry_t));
    if (NULL == entry)
    {
        status = EVT_POLL_ALLOC_ERR;
        goto exit;
    }

    entry->fd = fd;
    entry->cb = cb;
    entry->cb_data = cb_data;

    struct epoll_event ev = {0};
    ev.events = events;
    ev.data.ptr = entry;

    if (0 != epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev))
    {
        status = EVT_POLL_UNABLE_TO_REGISTER;
        goto exit;
    }

    ctx->entries[ctx->count++] = entry;
    status = EVT_POLL_SUCCESS;

exit:
    if (EVT_POLL_SUCCESS != status && entry)
    {
        free(entry);
    }

    return status;
}

poll_status_t pollctx_remove(poll_ctx_t *ctx, int fd)
{
    poll_status_t status = EVT_POLL_INVALID_ARGS;

    if (NULL == ctx || 0 > fd)
    {
        goto exit;
    }

    /* search for file descriptor within epoll instance */
    uint8_t index = 0;
    if (!pollctx_find(ctx, fd, &index))
    {
        status = EVT_POLL_INVALID_FD;
        goto exit;
    }

    /*
     * remove the registered fd and free underlying poll_entry_t structure
     * evt_poll does not close the underlying fd as we don't own it
     */
    if (0 != epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL))
    {
        status = EVT_POLL_UNABLE_TO_REMOVE;
        goto exit;
    }

    free(ctx->entries[index]);
    ctx->count--;

    /* rather than shifting all entries left, if index is less than current count, we just swap the last entry into the newly freed space */
    if (index < ctx->count)
    {
        ctx->entries[index] = ctx->entries[ctx->count];
    }

    ctx->entries[ctx->count] = NULL;
    status = EVT_POLL_SUCCESS;

exit:
    return status;
}

int pollctx_dispatch(poll_ctx_t *ctx, int timeout_ms)
{
    int num_events = EPOLL_GENERIC_ERR;
    struct epoll_event events[MAX_POLL_EVENTS] = {0};

    if (NULL == ctx)
    {
        goto exit;
    }

    do
    {
        /*
         * loop until we have the total number of events that were triggerd
         * if woke due to signal interrupt, continue to wait
         */
        num_events = epoll_wait(ctx->epoll_fd, events, MAX_POLL_EVENTS, timeout_ms);
    } while (EPOLL_GENERIC_ERR == num_events && EINTR == errno);

    /* An error occurred that wasn't EINTR */
    if (EPOLL_GENERIC_ERR == num_events)
    {
        goto exit;
    }

    /* Call the registered callback with the user supplied callback data */
    for (int i = 0; i < num_events; i++)
    {
        poll_entry_t *entry = events[i].data.ptr;
        if (entry->cb)
        {
            entry->cb(entry->fd, events[i].events, entry->cb_data);
        }
    }

exit:
    return num_events;
}

void pollctx_destroy(poll_ctx_t **ctx)
{
    if (NULL == ctx || NULL == *ctx)
    {
        return;
    }

    if ((*ctx)->entries)
    {
        for (uint8_t i = 0; i < (*ctx)->count; i++)
        {
            if ((*ctx)->entries[i])
            {
                free((*ctx)->entries[i]);
            }
        }

        free((*ctx)->entries);
    }

    close((*ctx)->epoll_fd);
    free(*ctx);
    *ctx = NULL;

    return;
}

static bool pollctx_find(poll_ctx_t *ctx, int fd, uint8_t *index)
{
    bool status = false;

    if (NULL == ctx || NULL == index)
    {
        goto exit;
    }

    /* check whether we have any actual entries, if not, just return */
    if (0 == ctx->count)
    {
        goto exit;
    }

    /* check whether supplied fd exists within the array */
    for (uint8_t i = 0; i < ctx->count; i++)
    {
        if (fd == ctx->entries[i]->fd)
        {
            *index = i;
            status = true;
            break;
        }
    }

exit:
    return status;
}
