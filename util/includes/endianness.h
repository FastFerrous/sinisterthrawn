#ifndef ENDIANNESS_H
#define ENDIANNESS_H

#include <stdint.h>
#include <stdbool.h>
#include "slice.h"

/* performs byte swap conversions from network <-> host from a provided subslice containing the value */
bool u64_swap_from_slice(const Slice *slice, uint64_t *result);
bool u32_swap_from_slice(const Slice *slice, uint32_t *result);
bool u16_swap_from_slice(const Slice *slice, uint16_t *result);

/* performs byte swap conversions from network <-> host from a provided value */
bool u64_swap(uint64_t value, uint64_t *result);
bool u32_swap(uint32_t value, uint32_t *result);
bool u16_swap(uint16_t value, uint16_t *result);

#endif
