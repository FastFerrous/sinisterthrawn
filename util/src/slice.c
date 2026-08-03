#include <stdint.h>
#include <stdlib.h>
#include "slice.h"

SliceStatus slice_new(Slice *slice, const void *data, uint64_t count, uint64_t element_size)
{
    SliceStatus status = SL_INVALID_PTR;

    if (NULL == slice || NULL == data)
    {
        goto exit;
    }

    slice->len = count;
    slice->element_size = element_size;
    slice->data = data;

    status = SL_OK;

exit:
    return status;
}

const void *slice_get(const Slice *slice, uint64_t index)
{
    if (NULL == slice || index >= slice->len)
    {
        return NULL;
    }

    return slice->data + (index * slice->element_size);
}

SliceStatus slice_subslice(const Slice *slice, uint64_t start, uint64_t end, Slice *subslice)
{
    if (NULL == slice || NULL == subslice)
    {
        return SL_INVALID_PTR;
    }

    if (start > end || start >= slice->len || end > slice->len)
    {
        return SL_OUT_OF_RANGE;
    }

    subslice->element_size = slice->element_size;
    subslice->len = end - start;
    subslice->data = slice->data + (start * slice->element_size);

    return SL_OK;
}

SliceStatus slice_len(const Slice *slice, uint64_t *len)
{
    if (NULL == slice || NULL == len)
    {
        return SL_INVALID_PTR;
    }

    *len = slice->len;
    return SL_OK;
}
