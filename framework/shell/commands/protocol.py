import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional
from os import urandom
from secrets import randbelow

# Maximum length of an `entire` packet, including header + data + padding
MAXIMUM_PACKET_LEN : int = 16384 

# Maximum length of the `data` field within the packet 
MAXIMUM_DATA_LEN: int = 8192
MAXIMUM_PADDING_LEN: int = 8192

# Shared packet header structure 
PACKET_HEADER_FMT: str = "!IHHBHH"

class Opcodes(IntEnum):
    NETSTAT = 0
    PS = 1
    LS = 2

class Retcodes(IntEnum):
    SUCCESS = 0
    INVALID_ARGS = 1

@dataclass
class PacketHeader:
    '''Shared packet header across all protocol requests'''
    total_packet_len: int
    total_chunks: int
    current_chunk: int
    opcode: int
    data_len: int
    pad_len: int

@dataclass
class Chunk:
    opcode: int
    total_chunks: int
    current_chunk: int
    data: bytes
    data_len: int

def get_padding() -> Optional[bytearray]: 
    """Calculates 5-15% of MAXIMUM_PADDING_LEN and returns padding on success or None on error"""

    # Percentage limitations for generating random padding bytes
    MINIMUM_PERCENTAGE: int = 5
    PADDING_PERCENTAGE_RANGE: int = 11

    # Calculate the percentage of padding and return that number of bytes 
    percentage = MINIMUM_PERCENTAGE + randbelow(PADDING_PERCENTAGE_RANGE)
    pad_len = (MAXIMUM_PADDING_LEN * percentage) // 100

    # If length is zero, set pad_len to random value within 1-255 
    if pad_len == 0:
        pad_len = 1 + randbelow(255)

    try:
        return urandom(pad_len)
    except OSError:
        return None

def build_packet(hdr: PacketHeader, data: bytes, padding: bytes) -> Optional[bytes]:
    """Packs header + data + padding into a single wire-ready buffer"""

    fmt : str = PACKET_HEADER_FMT + f"{len(data)}s" + f"{len(padding)}s"

    try:
        packet = struct.pack(
            fmt,
            hdr.total_packet_len,
            hdr.total_chunks,
            hdr.current_chunk,
            hdr.opcode,
            hdr.data_len,
            hdr.pad_len,
            data, 
            padding
        )

    except struct.error:
        return None

    return packet

def proto_read():
    pass 

def proto_write():
    pass 

# flow: every command only passes in opcode + optional data
# build packet will take in teh opcode + data and handle all chunking + padding 
# so no more get data and then saend
# we just send opcode + all data to proto_write. that will then internally call get padding, build packet etc. 
# caller will then await proto.read for intial response and then call again for any additional data required 



