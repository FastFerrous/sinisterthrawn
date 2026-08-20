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
} opcodes_t;

typedef struct chunk_t
{

} chunk_t;

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

#endif

// flow:
// each task will pack their data the way that its expected to be recvd on remote peer, has no clue how comms will handle. just raw application data
// comms_write will take that buffer and handle all chunking
// comms_write will then call into tls_conn vtable for writing the chunk data

// can most likely create some shared lib functions within proto, so its easier on the tls protocols to implement these. ie get padding, etc.

// modify python to use this chunking support for longer comms tasks, ie upload, download, etc

// may have this include the tls.h and then application speciifc files will import proto.h, it will call comms_write, comms_recv and pass in the tls_conn. that will do all the chunking of data and then call the vtable functions. this keeps application and libraries agnostic. if not, each tls lib has to handle chunking in an inverse and then backward way
// that design would mean application knows about proto, and proto can call into tls, but tls has no real clue about application or proto.

// chunk or intenral packet can be used and created to route traffic internal. needs data + data len + chunk counter + chunk index