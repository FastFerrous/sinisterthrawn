#include <stdlib.h>
#include <sys/random.h>
#include <string.h>
#include "proto.h"
#include "endianness.h"
#include "struct.h"

/* Used to create the percentage range of 5-15% for padding length calculation */
#define MINIMUM_PADDING_PERCENTAGE 5
#define PADDING_PERCENTAGE_MODULUS 11

/* validates inbound packets header and returns true on success or false on
 * error */
static bool validate_header(packet_header_t *hdr)
{
    bool status = false;

    if (NULL == hdr)
    {
        goto exit;
    }

    /* to avoid the caller needing to supply two buffers for the same outcome, a temporary buffer will be made to perform unpack operations */
    unsigned char buffer[sizeof(packet_header_t)] = {0};
    memcpy(buffer, hdr, sizeof(packet_header_t));

    if (STRUCT_OK != struct_unpack(
                         "IHHBHH",
                         buffer,
                         sizeof(packet_header_t),
                         &hdr->total_packet_len,
                         &hdr->total_chunks,
                         &hdr->current_chunk,
                         &hdr->opcode,
                         &hdr->data_len,
                         &hdr->pad_len))
    {
        goto exit;
    }

    /* validate total packet length and convert from network byte order */
    if (MAXIMUM_PACKET_LEN < hdr->total_packet_len)
    {
        goto exit;
    }

    /* validate that the current chunk does not exceed the total number of chunks,
     * ie malformed packet */
    if (hdr->current_chunk >= hdr->total_chunks)
    {
        goto exit;
    }

    /* validate that opcode doesnt exceed the backstop */
    if (OPCODE_MAXIMUM <= hdr->opcode)
    {
        goto exit;
    }

    /* validate that packet length matches expected values, data and padding
     * should not exceed 8192 bytes */
    if (MAXIMUM_DATA_LEN < hdr->data_len || MAXIMUM_PAD_LEN < hdr->pad_len)
    {
        goto exit;
    }

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
static unsigned char *get_padding(uint16_t *pad_len)
{
    bool status = false;
    unsigned char *buffer = NULL;

    if (NULL == pad_len)
    {
        goto exit;
    }

    /*
     * pad length will be 5-15% of the MAXIMUM_PAD_LEN value
     * using a random byte from /dev/urandom to determine percentage of padding via modulus
     * */
    uint8_t rand_byte = 0;
    if (0 > getrandom(&rand_byte, sizeof(uint8_t), GRND_NONBLOCK))
    {
        goto exit;
    }

    uint8_t percentage = MINIMUM_PADDING_PERCENTAGE + (rand_byte % PADDING_PERCENTAGE_MODULUS);
    uint16_t length = (MAXIMUM_PAD_LEN * percentage) / 100;

    /* if for some reason the length of the calculation is zero, set the minimum length to rand_byte. If that is zero, set to one */
    if (0 == length)
    {
        length = 0 != rand_byte ? rand_byte : sizeof(unsigned char);
    }

    /* allocate temporary buffer based on user supplied length to store random
     * bytes, if an error occurs free and null prior to return */
    buffer = calloc(1, length);
    if (NULL == buffer)
    {
        goto exit;
    }

    size_t bytes_read = 0;
    while (bytes_read < length)
    {
        ssize_t ret =
            getrandom(buffer + bytes_read, length - bytes_read, GRND_NONBLOCK);
        if (ret < 0)
        {
            goto exit;
        }

        bytes_read += ret;
    }

    /* set pad length for caller */
    *pad_len = length;

    status = true;

exit:
    if (!status)
    {
        free(buffer);
        buffer = NULL;
    }

    return buffer;
}

/* Uses supplied header, data, and padding and creates a serialized packet for writing over the socket */
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
        padding = get_padding(&pad_len);
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

/* simple helper function exposed to application for freeing chunks */
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
