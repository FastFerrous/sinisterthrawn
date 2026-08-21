#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include "tls.h"

#define MAXIMUM_PACKET_LEN 16384
#define MAXIMUM_DATA_LEN 8192
#define MAXIMUM_PAD_LEN 8192

typedef enum opcodes_t
{
    NETSTAT,
    PS,
    LS,

    /* opcodes are placed above this line, this is used for validation within the packet header */
    OPCODE_MAXIMUM
} opcodes_t;

typedef struct chunk_t
{
    /* used to for tracking */
    uint16_t total_chunks;
    uint16_t current_chunk;

    /* used for routing */
    opcodes_t opcode;

    /* opaque pointer for application specific data */
    unsigned char *data;
    uint16_t len;
} chunk_t;

/* shared packet header amongst inbound and outbound packets */
#pragma pack(push, 1)
typedef struct packet_header_t
{
    uint32_t total_packet_len;
    uint16_t total_chunks;
    uint16_t current_chunk;
    uint8_t opcode;
    uint16_t data_len;
    uint16_t pad_len;
} packet_header_t;
#pragma pack(pop)

/*
 * application layer will call proto_write or proto_read to handle protocol-level chunking
 * once protocol has chunked data appropriately, proto will call into the opaque tls library via
 * tls_send() or tls_recv() for actual socket operations
 */
tls_conn_status_t proto_write(struct tls_conn_t *conn, opcodes_t opcode, unsigned char *buf, size_t len);
tls_conn_status_t proto_read(struct tls_conn_t *conn, chunk_t *chunk);

#endif
