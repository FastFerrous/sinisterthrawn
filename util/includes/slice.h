#ifndef SLICE_H
#define SLICE_H

#include <stdint.h>

typedef enum SliceStatus
{
    SL_OK,
    SL_INVALID_PTR,
    SL_OUT_OF_RANGE
} SliceStatus;

typedef struct Slice
{
    const unsigned char *data;
    uint64_t len;
    uint64_t element_size;
} Slice;

/*
 * creates a `fat` pointer similar to rust's &[T]
 * user is responsible for ensuring that data points to the correct start point and that the count * element_size doesnt overflow
 * no allocations are made. Slice structure is built on the stack and underlying data is a const ref
 * this implementation is strictly for `borrowing`
 */
SliceStatus slice_new(Slice *slice, const void *data, uint64_t count, uint64_t element_size);

/* get a const ref to the underlying data at specified index within the slice */
const void *slice_get(const Slice *slice, uint64_t index);

/* create a new slice out of an existing slice; end is exclusive */
SliceStatus slice_subslice(const Slice *slice, uint64_t start, uint64_t end, Slice *subslice);

/* return number of elements within the slice */
SliceStatus slice_len(const Slice *slice, uint64_t *len);

#endif