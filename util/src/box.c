#include <stdlib.h>
#include "box.h"

/*
 * currently a box only stores the allocated buffer and the size of the allocation
 * in future builds, this could be expanded to emulate other `smart_ptr` functions from other languages
 */
typedef struct box_t
{
    void *data;
    uint32_t size;
} box_t;

box_t *box_new(uint32_t count, uint32_t size)
{
    if (0 == count || 0 == size || UINT32_MAX / size < count)
    {
        return NULL;
    }

    box_t *box = calloc(1, sizeof(box_t));
    if (NULL == box)
    {
        return NULL;
    }

    box->size = count * size;
    box->data = calloc(1, box->size);
    if (NULL == box->data)
    {
        free(box);
        return NULL;
    }

    return box;
}

void box_free(box_t **box)
{
    if (NULL == box || NULL == *box)
    {
        return;
    }

    if ((*box)->data)
    {
        free((*box)->data);
    }

    free(*box);
    *box = NULL;

    return;
}

void *box_data(const box_t *box)
{
    if (NULL == box || NULL == box->data)
    {
        return NULL;
    }

    return box->data;
}

uint32_t box_size(const box_t *box)
{
    if (NULL == box)
    {
        return 0;
    }

    return box->size;
}
