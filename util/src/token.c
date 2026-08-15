#include <stdlib.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include "token.h"

typedef enum TokenStatus
{
    TOKEN_OK,
    TOKEN_ALLOC_ERR,
    TOKEN_MUTEX_ERR,
    TOKEN_COND_ERR,
} TokenStatus;

typedef struct CancellationToken
{
    /* reference counter tracking */
    int reference_count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    /* tracks whether the token has been signaled to shutdown */
    atomic_bool status;
    int event;
} CancellationToken;

CancellationToken *token_create()
{
    TokenStatus status = TOKEN_ALLOC_ERR;

    CancellationToken *token = calloc(1, sizeof(CancellationToken));
    if (NULL == token)
    {
        goto exit;
    }

    /* intitialize shutdown status atomic and eventfd for poll operations */
    atomic_init(&token->status, false);

    token->event = eventfd(0, EFD_NONBLOCK);
    if (INVALID_EVENTFD_DESCRIPTOR == token->event)
    {
        goto exit;
    }

    /* intitialize reference counter */
    if (pthread_mutex_init(&token->mutex, NULL))
    {
        status = TOKEN_MUTEX_ERR;
        goto exit;
    }

    if (pthread_cond_init(&token->cond, NULL))
    {
        status = TOKEN_COND_ERR;
        goto exit;
    }

    status = TOKEN_OK;

exit:

    switch (status)
    {
    case TOKEN_COND_ERR:
        pthread_mutex_destroy(&token->mutex);
        /* fallthrough */
    case TOKEN_MUTEX_ERR:
        close(token->event);
        /* fallthrough */
    case TOKEN_ALLOC_ERR:
        if (token)
        {
            free(token);
            token = NULL;
        }
        break;
    default:
        break;
    }

    return token;
}

bool token_is_cancelled(const CancellationToken *token)
{
    if (NULL == token)
    {
        return false;
    }

    return atomic_load(&token->status);
}

int token_get_event(const CancellationToken *token)
{
    if (NULL == token)
    {
        return INVALID_EVENTFD_DESCRIPTOR;
    }

    return token->event;
}

bool token_shutdown(CancellationToken *token)
{
    if (NULL == token)
    {
        return false;
    }

    /* mutex is not necessarily needed for the status modification or write operation; however, is used to force syncronization */
    pthread_mutex_lock(&token->mutex);

    atomic_store(&token->status, true);

    /*
     * ignoring return result from write as validity checks on fd have already occured above
     * returning false here would only force leaks of the fd and structure
     * the `status` atomic is the key identifier for whether shutdown has been instructed, eventfd is used purely for polling
     */
    const uint64_t signal = 1;
    write(token->event, &signal, sizeof(signal));

    pthread_mutex_unlock(&token->mutex);

    return true;
}

bool token_acquire(CancellationToken *token)
{
    bool status = false;
    bool is_locked = false;

    if (NULL == token)
    {
        goto exit;
    }

    pthread_mutex_lock(&token->mutex);

    is_locked = true;

    if (atomic_load(&token->status))
    {
        goto exit;
    }

    token->reference_count += 1;
    status = true;

exit:
    if (is_locked)
    {
        pthread_mutex_unlock(&token->mutex);
    }

    return status;
}

bool token_release(CancellationToken *token)
{
    bool status = false;
    bool is_locked = false;

    if (NULL == token)
    {
        goto exit;
    }

    pthread_mutex_lock(&token->mutex);

    is_locked = true;

    if (0 == token->reference_count)
    {
        goto exit;
    }

    if (0 == (token->reference_count -= 1))
    {
        pthread_cond_signal(&token->cond);
    }

    status = true;

exit:
    if (is_locked)
    {
        pthread_mutex_unlock(&token->mutex);
    }

    return status;
}

bool token_destroy(CancellationToken **token)
{
    if (NULL == token || NULL == *token)
    {
        return false;
    }

    /* ignoring return val as pointer has already been validated */
    token_shutdown(*token);

    pthread_mutex_lock(&(*token)->mutex);

    /* block until all callers have released their `reference` */
    while (0 != (*token)->reference_count)
    {
        pthread_cond_wait(&(*token)->cond, &(*token)->mutex);
    }

    pthread_mutex_unlock(&(*token)->mutex);

    close((*token)->event);
    pthread_mutex_destroy(&(*token)->mutex);
    pthread_cond_destroy(&(*token)->cond);

    free(*token);
    *token = NULL;

    return true;
}
