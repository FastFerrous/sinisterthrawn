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

class Opcodes(IntEnum):
    NETSTAT = 0

class Retcodes(IntEnum):
    SUCCESS = 0
    INVALID_ARGS = 1

@dataclass
class PacketHeader():
    '''Shared packet header across all protocol requests'''
    packet_len: int 
    opcode: int 
    data_len: int 
    padding_len: int 

PACKET_HEADER_FMT : str = "!IBHH"

def get_padding(packet_length: int) -> Optional[bytearray]: 
    '''Calculates a random percentage between 5-20% of the remaining packet length and returns a random bytearray of that length'''

    # Percentage limitations for generating padding
    MAXIMUM_PERCENTAGE: int = 20
    MINIMUM_PERCENTAGE: int = 5 

    # determine remaining byte length within total packet, padding cannot exceed 8192 bytes even if remaining is larger than that
    remaining = MAXIMUM_PACKET_LEN - packet_length
    if remaining <= 0:
        return None 

    # check whether the amount remaining is less than maximum padding length, and if not, set to the maximum allowed
    cap = min(remaining, MAXIMUM_PADDING_LEN)
    percentage = MINIMUM_PERCENTAGE + randbelow(MAXIMUM_PERCENTAGE  - MINIMUM_PERCENTAGE + 1)  
    pad_len = max(1, (cap * percentage) // 100)

    try:
        return urandom(pad_len)
    except OSError:
        return None



