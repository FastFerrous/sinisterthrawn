#ifndef STRUCT_H
#define STRUCT_H

#include <stdint.h>

/*
 * Limited C implementation of python3 struct pack and unpack

 * FMT support is limited to:
 *      - B (unsigned char)
 *      - H (unsigned short)
 *      - I (unsigned long)
 *      - Q (unsigned long long)
 *      - s (char [])
 */

typedef enum struct_status_t
{
    STRUCT_OK,
    STRUCT_INVALID_ARGS,
    STRUCT_INVALID_FMT,
    STRUCT_BUFFER_OVERFLOW
} struct_status_t;

/*
 * Packs the supplied buffer in network byte order via the specifications listed in `fmt`
 * Caller is responsible for ensuring the supplied buffer is large enough to fit the `fmt` requirements
 * Caller is responsible for ensuring the correct arguments are supplied to avoid any UB
 */
struct_status_t struct_pack(const char *fmt, unsigned char *buffer, uint32_t size, ...);

/*
 * Unpacks the supplied `packed_buffer` from network byte order via the supplied specification listed in `fmt`
 * Caller is responsible for ensuring that the buffer and len are adequate for the unpack request
 * Supplied VA args will be populated as the `fmt` string is parsed, ie IIB would require three pointers for two uint32 and one uint8
 * Caller is responsible for freeing any unpacked string, ie 10s. Allocation occurs during unpack
 */
struct_status_t struct_unpack(const char *fmt, unsigned char *packed_buffer, uint32_t size, ...);

#endif
