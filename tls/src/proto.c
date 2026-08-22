#include <stdlib.h>
#include <sys/random.h>
#include <string.h>
#include "proto.h"
#include "endianness.h"
#include "struct.h"

/* validates inbound packets header and returns true on success or false on
 * error */
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

    /* validate that the current chunk does not exceed the total number of chunks,
     * ie malformed packet */
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

    /* validate that packet length matches expected values, data and padding
     * should not exceed 8192 bytes */
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

    /* validate that the header length matches sizeof(header) + data and pad
     * lengths, if not, malformed */
    if (hdr->total_packet_len !=
        sizeof(packet_header_t) + hdr->data_len + hdr->pad_len)
    {
        goto exit;
    }

    status = true;

exit:
    return status;
}

/*
 * generate random padding data that is crypto secure for appending onto packets
 * for wire variation underlying function is blocking; however, flag is set to
 * avoid that behavior tls libraries will all have already seeded rng, so there
 * should be no issue with this; however, if problems start to occur, we could
 * manually open random/urandom and read the byte count manually
 */
static unsigned char *get_padding(size_t data_len, uint16_t *pad_len)
{
    bool status = false;
    unsigned char *buffer = NULL;

    if (0 == data_len)
    {
        goto exit;
    }

    /* allocate temporary buffer based on user supplied length to store random
     * bytes, if an error occurs free and null prior to return */
    buffer = calloc(1, data_len);
    if (NULL == buffer)
    {
        goto exit;
    }

    size_t bytes_read = 0;
    while (bytes_read < data_len)
    {
        ssize_t ret =
            getrandom(buffer + bytes_read, data_len - bytes_read, GRND_NONBLOCK);
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

static unsigned char *build_packet(packet_header_t *hdr, unsigned char *data, unsigned char *padding)
{
    bool status = false;
    unsigned char *packet = NULL;

    if (NULL == hdr || NULL == data || NULL == padding)
    {
        goto exit;
    }

    /* allocate total packet length */
    packet = calloc(1, hdr->total_packet_len);
    if (NULL == packet)
    {
        goto exit;
    }

    /* pack the header */
    if (STRUCT_OK != struct_pack(
                         "IHHBHH",
                         packet,
                         sizeof(packet_header_t),
                         hdr->total_packet_len,
                         hdr->total_chunks,
                         hdr->current_chunk,
                         hdr->opcode,
                         hdr->data_len,
                         hdr->pad_len))
    {
        goto exit;
    }

    /* mempcy data + padding, could have used struct pack, but avoiding fmt string creation via snprintf, etc. */
    memcpy(packet + sizeof(packet_header_t), data, hdr->data_len);
    memcpy(packet + sizeof(packet_header_t) + hdr->data_len, padding, hdr->pad_len);

    status = true;

exit:
    if (!status && packet)
    {
        free(packet);
        packet = NULL;
    }

    return packet;
}

tls_conn_status_t proto_write(struct tls_conn_t *conn, opcodes_t opcode,
                              unsigned char *buf, size_t len)
{
    unsigned char *packet = NULL;
    unsigned char *padding = NULL;
    tls_conn_status_t status = TLS_INVALID_ARGS;

    if (NULL == conn || NULL == conn->send || NULL == buf || 0 == len)
    {
        goto exit;
    }

    /*
     * regular division will drop any remaining float, using this to emulate ceil
     * adding 8191, ensures that if there were any remainder, it pushes over the threshold
     */
    uint16_t chunk_count = (len + MAXIMUM_DATA_LEN - 1) / MAXIMUM_DATA_LEN;

    /* iterate through chunk counter, allocate and populate the chunk and write over the socket */
    for (uint16_t i = 0; i < chunk_count; i++)
    {
        /* check whether we are under max and need to handle smaller writes */
        uint16_t offset = i * MAXIMUM_DATA_LEN;
        uint16_t data_len = MAXIMUM_DATA_LEN < (len - offset) ? MAXIMUM_DATA_LEN : (uint16_t)(len - offset);

        /* get padding for packet variation */
        uint16_t pad_len = 0;
        unsigned char *padding = NULL; // needs ot be a percent of the data len. so data len will get supplid and 5-15% of that will be calculated and returned
        if (NULL == padding)
        {
            status = TLS_ALLOC_ERR;
            goto exit;
        }

        /* build out packet header and then serialize packet for socket write */
        packet_header_t hdr = {
            .current_chunk = i,
            .total_chunks = chunk_count,
            .data_len = data_len,
            .pad_len = pad_len,
            .opcode = opcode,
            .total_packet_len = sizeof(packet_header_t) + data_len + pad_len};

        packet = build_packet(&hdr, buf + offset, padding);
        if (NULL == packet)
        {
            status = TLS_ALLOC_ERR;
            goto exit;
        }

        if (TLS_SUCCESS != conn->send(conn, packet, sizeof(packet_header_t) + data_len + pad_len))
        {
            status = TLS_WRITE_ERR;
            goto exit;
        }

        /* free packet + padding for next iteration */
        free(padding);
        padding = NULL;

        free(packet);
        packet = NULL;
    }

    status = TLS_SUCCESS;

exit:
    if (packet)
    {
        free(packet);
    }

    if (padding)
    {
        free(padding);
    }

    return status;
}

tls_conn_status_t proto_read(struct tls_conn_t *conn, chunk_t *chunk)
{
    unsigned char *data = NULL;
    tls_conn_status_t status = TLS_INVALID_PTR;

    if (NULL == conn || NULL == conn->recv || NULL == chunk)
    {
        goto exit;
    }

    /* attempt to read and validate packet header */
    packet_header_t hdr = {0};
    if (TLS_SUCCESS !=
        conn->recv(conn, (unsigned char *)&hdr, sizeof(packet_header_t)))
    {
        status = TLS_READ_ERR;
        goto exit;
    }

    if (!validate_header(&hdr))
    {
        status = TLS_INVALID_PACKET;
        goto exit;
    }

    /* read in remaining session data */
    data = calloc(1, hdr.total_packet_len - sizeof(packet_header_t));
    if (NULL == data)
    {
        status = TLS_ALLOC_ERR;
        goto exit;
    }

    if (TLS_SUCCESS != conn->recv(conn, data, hdr.total_packet_len - sizeof(packet_header_t)))
    {
        status = TLS_READ_ERR;
        goto exit;
    }

    /* populate chunk and return to caller */
    chunk->opcode = hdr.opcode;
    chunk->total_chunks = hdr.total_chunks;
    chunk->current_chunk = hdr.current_chunk;
    chunk->len = hdr.data_len;
    chunk->data = calloc(1, chunk->len);
    if (NULL == chunk->data)
    {
        status = TLS_ALLOC_ERR;
        goto exit;
    }

    memcpy(chunk->data, data, hdr.data_len);

    status = TLS_SUCCESS;

exit:
    if (data)
    {
        free(data);
    }

    return status;
}

void chunk_free(chunk_t **chunk)
{
    if (NULL == chunk || NULL == *chunk)
    {
        goto exit;
    }

    if ((*chunk)->data)
    {
        free((*chunk)->data);
    }

    free(*chunk);
    *chunk = NULL;

exit:
    return;
}

// flow: app -> proto -> tls library

// todo: get padding within proto_write.. padding should return the pointer + pointer length. so it takes in data size, calculates padding and returns both values
// todo: use struct to unpack the response for proto_read -> validate_header
