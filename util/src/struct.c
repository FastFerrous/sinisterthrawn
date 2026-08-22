#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include "struct.h"
#include "endianness.h"

#define BASE10 10

/* supported format specifiers */
typedef enum fmt_types_t
{
    FMT_B,
    FMT_H,
    FMT_I,
    FMT_Q,
    FMT_S,
    FMT_INVALID
} fmt_types_t;

/* parses the user supplied `fmt` string and returns T and sizeof(T) */
static bool parse_fmt(const char **fmt, fmt_types_t *type, uint32_t *size)
{
    bool status = false;

    if (NULL == fmt || NULL == *fmt || NULL == type || NULL == size)
    {
        goto exit;
    }

    /*
     * stores the count of bytes that will be packed for string operations
     * ie 44s would store 44 to be written into *size
     */
    bool has_count = false;
    uint32_t count = 0;
    while (**fmt >= '0' && **fmt <= '9')
    {
        has_count = true;
        count = (count * BASE10) + (uint32_t)(**fmt - '0');
        (*fmt)++;
    }

    /* count values are only supported for string operations, ie 44s. 4I would not permitted */
    if (has_count && 's' != **fmt)
    {
        goto exit;
    }

    switch (**fmt)
    {
    case 'B':
        *type = FMT_B;
        *size = sizeof(uint8_t);
        break;

    case 'H':
        *type = FMT_H;
        *size = sizeof(uint16_t);
        break;

    case 'I':
        *type = FMT_I;
        *size = sizeof(uint32_t);
        break;

    case 'Q':
        *type = FMT_Q;
        *size = sizeof(uint64_t);
        break;

    case 's':
        /* string operations must include a numeric counter */
        if (!has_count || 0 == count)
        {
            goto exit;
        }

        *type = FMT_S;
        *size = count;

        break;

    default:
        goto exit;
    }

    (*fmt)++;

    status = true;

exit:
    return status;
}

/* performs packing and unpacking of specified T */
static bool pack_u8(va_list *args, unsigned char *buffer, uint32_t index)
{
    if (NULL == args || NULL == buffer)
    {
        return false;
    }

    unsigned int value = va_arg(*args, unsigned int);
    buffer[index] = (uint8_t)value;

    return true;
}

static bool pack_u16(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;
    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    uint16_t value = 0;
    unsigned int arg = va_arg(*args, unsigned int);

    if (!u16_swap(arg, &value))
    {
        goto exit;
    }

    memcpy(buffer + index, &value, sizeof(uint16_t));
    status = true;

exit:
    return status;
}

static bool pack_u32(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    uint32_t value = 0;
    uint32_t arg = va_arg(*args, uint32_t);

    if (!u32_swap(arg, &value))
    {
        goto exit;
    }

    memcpy(buffer + index, &value, sizeof(uint32_t));
    status = true;

exit:
    return status;
}

static bool pack_u64(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    uint64_t value = 0;
    uint64_t arg = va_arg(*args, uint64_t);

    if (!u64_swap(arg, &value))
    {
        goto exit;
    }

    memcpy(buffer + index, &value, sizeof(uint64_t));
    status = true;

exit:
    return status;
}

static bool pack_str(va_list *args, uint32_t len, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer || 0 == len)
    {
        goto exit;
    }

    const unsigned char *src = va_arg(*args, const unsigned char *);
    if (NULL == src)
    {
        goto exit;
    }

    memcpy(buffer + index, src, len);
    status = true;

exit:
    return status;
}

static bool unpack_u8(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    uint8_t *ptr = va_arg(*args, uint8_t *);
    if (NULL == ptr)
    {
        goto exit;
    }

    *ptr = buffer[index];
    status = true;

exit:
    return status;
}

static bool unpack_u16(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    /* extract user supplied pointer to store unpacked data */
    uint16_t *ptr = va_arg(*args, uint16_t *);
    if (NULL == ptr)
    {
        goto exit;
    }

    uint16_t packed_value = 0;
    memcpy(&packed_value, buffer + index, sizeof(uint16_t));

    uint16_t value = 0;
    if (!u16_swap(packed_value, &value))
    {
        goto exit;
    }

    *ptr = value;

    status = true;

exit:
    return status;
}

static bool unpack_u32(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    /* extract user supplied pointer to store unpacked data */
    uint32_t *ptr = va_arg(*args, uint32_t *);
    if (NULL == ptr)
    {
        goto exit;
    }

    uint32_t packed_value = 0;
    memcpy(&packed_value, buffer + index, sizeof(uint32_t));

    uint32_t value = 0;
    if (!u32_swap(packed_value, &value))
    {
        goto exit;
    }

    *ptr = value;

    status = true;

exit:
    return status;
}

static bool unpack_u64(va_list *args, unsigned char *buffer, uint32_t index)
{
    bool status = false;

    if (NULL == args || NULL == buffer)
    {
        goto exit;
    }

    /* extract user supplied pointer to store unpacked data */
    uint64_t *ptr = va_arg(*args, uint64_t *);
    if (NULL == ptr)
    {
        goto exit;
    }

    uint64_t packed_value = 0;
    memcpy(&packed_value, buffer + index, sizeof(uint64_t));

    uint64_t value = 0;
    if (!u64_swap(packed_value, &value))
    {
        goto exit;
    }

    *ptr = value;

    status = true;

exit:
    return status;
}

static bool unpack_str(va_list *args, uint32_t len, unsigned char *buffer, uint32_t index)
{
    bool status = false;
    unsigned char *temp = NULL;

    if (NULL == args || NULL == buffer || 0 == len)
    {
        goto exit;
    }

    /* extract user supplied pointer to store unpacked data */
    unsigned char **ptr = va_arg(*args, unsigned char **);
    if (NULL == ptr)
    {
        goto exit;
    }

    /* allocate memory to store the extracted packed string */
    temp = calloc(1, len);
    if (NULL == temp)
    {
        goto exit;
    }

    /* extract string and assing to user supplied pointer */
    memcpy(temp, buffer + index, len);
    *ptr = temp;

    status = true;

exit:
    if (!status && temp)
    {
        free(temp);
    }

    return status;
}

/* exposed `pack` and `unpack` */
struct_status_t struct_pack(const char *fmt, unsigned char *buffer, uint32_t size, ...)
{
    struct_status_t status = STRUCT_INVALID_ARGS;
    bool va_setup = false;

    if (NULL == fmt || NULL == buffer || 0 == size)
    {
        goto exit;
    }

    /* initialize va args, these are the expected values that should align with the fmt string */
    va_list args = {0};
    va_start(args, size);

    va_setup = true;

    /* used to track write offsets within the user supplied buffer during pack `write` operations */
    uint32_t index = 0;

    while ('\0' != *fmt)
    {
        /* attempt to parse the next `type` within the supplied fmt string  */
        fmt_types_t type = FMT_INVALID;
        uint32_t len = 0;

        if (!parse_fmt(&fmt, &type, &len))
        {
            status = STRUCT_INVALID_FMT;
            goto exit;
        }

        /* before `packing`, ensure that the buffer is large enough to store supplied data type */
        if (len > size - index)
        {
            status = STRUCT_BUFFER_OVERFLOW;
            goto exit;
        }

        switch (type)
        {
        case FMT_B:
            if (!pack_u8(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_H:
            if (!pack_u16(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_I:
            if (!pack_u32(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_Q:
            if (!pack_u64(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_S:
            if (!pack_str(&args, len, buffer, index))
            {
                goto exit;
            }
            break;

        default:
            status = STRUCT_INVALID_FMT;
            goto exit;
        }

        index += len;
    }

    status = STRUCT_OK;

exit:
    if (va_setup)
    {
        va_end(args);
    }

    return status;
}

struct_status_t struct_unpack(const char *fmt, unsigned char *buffer, uint32_t size, ...)
{
    struct_status_t status = STRUCT_INVALID_ARGS;
    bool va_setup = false;

    if (NULL == fmt || NULL == buffer || 0 == size)
    {
        goto exit;
    }

    /* initialize va args, these are the expected values that should align with the fmt string */
    va_list args = {0};
    va_start(args, size);

    va_setup = true;

    /* used to track write offsets within the user supplied buffer during pack `write` operations */
    uint32_t index = 0;

    while ('\0' != *fmt)
    {
        /* attempt to parse the next `type` within the supplied fmt string  */
        fmt_types_t type = FMT_INVALID;
        uint32_t len = 0;

        if (!parse_fmt(&fmt, &type, &len))
        {
            status = STRUCT_INVALID_FMT;
            goto exit;
        }

        /* before `unpacking`, ensure supplied buffer is large enough to extract the specified type size */
        if (len > size - index)
        {
            status = STRUCT_BUFFER_OVERFLOW;
            goto exit;
        }

        switch (type)
        {
        case FMT_B:
            if (!unpack_u8(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_H:
            if (!unpack_u16(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_I:
            if (!unpack_u32(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_Q:
            if (!unpack_u64(&args, buffer, index))
            {
                goto exit;
            }
            break;

        case FMT_S:
            if (!unpack_str(&args, len, buffer, index))
            {
                goto exit;
            }
            break;

        default:
            status = STRUCT_INVALID_FMT;
            goto exit;
        }

        index += len;
    }

    status = STRUCT_OK;

exit:
    if (va_setup)
    {
        va_end(args);
    }

    return status;
}
