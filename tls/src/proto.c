#include <stdlib.h>
#include <sys/random.h>
#include "proto.h"
#include "endianness.h"

/* validates inbound packets header and returns true on success or false on error */
static bool validate_header(packet_header_t *hdr)
{
    bool status = false;

    if (NULL == hdr)
    {
        goto exit;
    }

    /* validate total packet length and convert from network byte order */
    uint32_t total_len = 0;
    if (!u32_swap(hdr->total_packet_len, &total_len))
    {
        goto exit;
    }

    if (MAXIMUM_PACKET_LEN < total_len)
    {
        goto exit;
    }

    hdr->total_packet_len = total_len;

    /* validate that the current chunk does not exceed the total number of chunks, ie malformed packet */
    uint16_t current_chunk = 0;
    uint16_t total_chunks = 0;

    if (!u16_swap(hdr->current_chunk, &current_chunk))
    {
        goto exit;
    }

    if (!u16_swap(hdr->total_chunks, &total_chunks))
    {
        goto exit;
    }

    if (current_chunk >= total_chunks)
    {
        goto exit;
    }

    hdr->current_chunk = current_chunk;
    hdr->total_chunks = total_chunks;

    /* validate that opcode doesnt exceed the backstop */
    if (OPCODE_MAXIMUM <= hdr->opcode)
    {
        goto exit;
    }

    /* validate that packet length matches expected values, data and padding should not exceed 8192 bytes */
    uint16_t data_len = 0;
    uint16_t pad_len = 0;

    if (!u16_swap(hdr->data_len, &data_len))
    {
        goto exit;
    }

    if (!u16_swap(hdr->pad_len, &pad_len))
    {
        goto exit;
    }

    if (MAXIMUM_DATA_LEN < data_len || MAXIMUM_PAD_LEN < pad_len)
    {
        goto exit;
    }

    hdr->data_len = data_len;
    hdr->pad_len = pad_len;

    /* validate that the header length matches sizeof(header) + data and pad lengths, if not, malformed */
    if (hdr->total_packet_len != sizeof(packet_header_t) + hdr->data_len + hdr->pad_len)
    {
        goto exit;
    }

    status = true;

exit:
    return status;
}

/*
 * generate random padding data that is crypto secure for appending onto packets for wire variation
 * underlying function is blocking; however, flag is set to avoid that behavior
 * tls libraries will all have already seeded rng, so there should be no issue with this; however,
 * if problems start to occur, we could manually open random/urandom and read the byte count manually
 */
static unsigned char *get_padding(size_t length)
{
    bool status = false;
    unsigned char *buffer = NULL;

    if (0 == length)
    {
        goto exit;
    }

    /* allocate temporary buffer based on user supplied length to store random bytes, if an error occurs free and null prior to return */
    buffer = calloc(1, length);
    if (NULL == buffer)
    {
        goto exit;
    }

    size_t bytes_read = 0;
    while (bytes_read < length)
    {
        ssize_t ret = getrandom(buffer + bytes_read, length - bytes_read, GRND_NONBLOCK);
        if (ret < 0)
        {
            goto exit;
        }

        bytes_read += ret;
    }

    status = true;

exit:
    if (!status)
    {
        free(buffer);
        buffer = NULL;
    }

    return buffer;
}

static bool chunk_outbound_data(); // chunks data and calls tls library. may eb able to just store inside proto_write

tls_conn_status_t proto_write(struct tls_conn_t *conn, opcodes_t opcode, unsigned char *buf, size_t len)
{
    return TLS_CONNECT_ERR;
    // pack the data according to our protocol, write each chunks
}

tls_conn_status_t proto_read(struct tls_conn_t *conn, chunk_t *chunk)
{
    chunk_t *temp_chunk = NULL;
    tls_conn_status_t status = TLS_INVALID_PTR;

    if (NULL == conn || NULL == conn->recv || NULL == chunk)
    {
        goto exit;
    }

    /* attempt to read and validate packet header */
    packet_header_t hdr = {0};
    if (TLS_SUCCESS != conn->recv(conn, (unsigned char *)&hdr, sizeof(packet_header_t)))
    {
        status = TLS_READ_ERR;
        goto exit;
    }

    if (!validate_header(&hdr))
    {
        status = TLS_INVALID_PACKET;
        goto exit;
    }

    // allocate actual required length
    // read in remaining part of packet and discard the padding.
    // use a temp chunk, do all reading, etc. and then just populate their chunmk accordingly

    status = TLS_SUCCESS;

exit:
    if (TLS_SUCCESS != status && temp_chunk)
    {
        // chunk_free(&temp_chunk);
    }

    return status;
}

// flow: app -> proto -> tls library

// todo:  make a chunk_allocate and chunk_free