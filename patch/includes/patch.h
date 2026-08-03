#ifndef PATCH_H
#define PATCH_H

#include <stdbool.h>
#include <stdint.h>
#include "slice.h"

#define STAMPED_BUFFER_LEN 2048
#define SPKI_HASH_LEN 32

typedef enum config_mode_t
{
    LISTEN,
    CALLBACK
} config_mode_t;

typedef struct stamped_config_t
{
    uint8_t key;
    uint8_t mode;
    uint8_t sleep;
    uint16_t port;
    Slice spki;
    Slice address;
    Slice public_key;
    Slice private_key;
    uint16_t interval;
    uint8_t max_cb;
    Slice sni;
} stamped_config_t;

/* attempts to parse and store embedded configuration. True on success or False on failure */
bool parse_config(stamped_config_t *config);

#endif