#include <stdlib.h>
#include "endianness.h"
#include "slice.h"
#include "debug.h"

bool u64_swap_from_slice(const Slice *slice, uint64_t *result)
{
    if (NULL == slice || NULL == result)
    {
        return false;
    }

    if (sizeof(uint64_t) > slice->len * sizeof(uint64_t))
    {
        return false;
    }

    *result = (uint64_t)slice->data[0] << 56 | (uint64_t)slice->data[1] << 48 |
              (uint64_t)slice->data[2] << 40 | (uint64_t)slice->data[3] << 32 |
              (uint64_t)slice->data[4] << 24 | (uint64_t)slice->data[5] << 16 |
              (uint64_t)slice->data[6] << 8 | (uint64_t)slice->data[7];
    return true;
}

bool u32_swap_from_slice(const Slice *slice, uint32_t *result)
{
    if (NULL == slice || NULL == result)
    {
        return false;
    }

    if (sizeof(uint32_t) > slice->len * sizeof(uint32_t))
    {
        return false;
    }

    *result = (uint32_t)slice->data[0] << 24 | (uint32_t)slice->data[1] << 16 |
              (uint32_t)slice->data[2] << 8 | (uint32_t)slice->data[3];

    return true;
}

bool u16_swap_from_slice(const Slice *slice, uint16_t *result)
{
    if (NULL == slice || NULL == result)
    {
        return false;
    }

    if (sizeof(uint16_t) > slice->len * sizeof(uint16_t))
    {
        return false;
    }

    *result =
        slice->data[0] << 8 | slice->data[1];

    return true;
}

bool u64_swap(uint64_t value, uint64_t *result)
{
    if (NULL == result)
    {
        return false;
    }

    /* cast value to byte pointer for shifting into result */
    uint8_t *bytes = (uint8_t *)&value;
    *result = (uint64_t)bytes[0] << 56 | (uint64_t)bytes[1] << 48 |
              (uint64_t)bytes[2] << 40 | (uint64_t)bytes[3] << 32 |
              (uint64_t)bytes[4] << 24 | (uint64_t)bytes[5] << 16 |
              (uint64_t)bytes[6] << 8 | (uint64_t)bytes[7];

    return true;
}

bool u32_swap(uint32_t value, uint32_t *result)
{
    if (NULL == result)
    {
        return false;
    }

    uint8_t *bytes = (uint8_t *)&value;
    *result = (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 |
              (uint32_t)bytes[2] << 8 | (uint32_t)bytes[3];

    return true;
}

bool u16_swap(uint16_t value, uint16_t *result)
{
    if (NULL == result)
    {
        return false;
    }

    uint8_t *bytes = (uint8_t *)&value;
    *result = (uint16_t)(bytes[0] << 8 | bytes[1]);

    return true;
}
