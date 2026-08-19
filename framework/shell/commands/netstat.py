import struct 
from typing import Optional, List
from shell.commands.protocol import PacketHeader, PACKET_HEADER_FMT, get_padding, Opcodes   

# temp 

class Netstat:
    def __init__(self):
        self.usage: str = "usage: netstat"
        self.connections: Optional[List] = None

    def pack_request(self) -> Optional[bytearray]:
        """packs netstat request via struct.pack() into a singular buffer for writing over socket"""

        try: 
            padding = get_padding(struct.calcsize(PACKET_HEADER_FMT))
        except struct.error:
            return None 
        
        fmt: str = PACKET_HEADER_FMT + f"{len(padding)}s"

        try: 
            packet = struct.pack(fmt, 
                                 struct.calcsize(PACKET_HEADER_FMT) + len(padding), 
                                 Opcodes.NETSTAT, 
                                 0, 
                                 len(padding), 
                                 padding)
        except struct.error:
            return None 

        return packet 

