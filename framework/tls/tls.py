import ssl
import socket
import asyncio
import logging
from pathlib import Path
from enum import IntEnum
from collections.abc import Callable


class Mode(IntEnum):
    SERVER = (0,)
    CLIENT = 1


class Tls:
    """Serves as single entrypoint for tls operations, provides both server and client modes"""

    def __init__(self, address: str, port: int, certs_dir: Path, mode: bool):
        self.host: str = address
        self.port: int = port
        self.certs: Path = certs_dir
        self.mode: Mode = Mode.SERVER if mode else Mode.CLIENT
        self.server: asyncio.Server | None = None
        self.sock: socket.socket | None = None
        self.log: logging.Logger = logging.getLogger("framework")

    async def create_listener(
        self,
        on_connect_cb: Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
    ) -> bool:
        """Creates asyncio listener and awaits inbound client connections"""

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        try:
            ctx.load_cert_chain(
                f"{self.certs}/server.crt", f"{self.certs}/server.key"
            )

            ctx.load_verify_locations(f"{self.certs}/ca.crt")
            ctx.verify_mode = ssl.CERT_REQUIRED

        except FileNotFoundError as error:
            self.log.warning(f"{error}")
            return False

        try:
            self.server = await asyncio.start_server(
                on_connect_cb, 
                str(self.host), 
                self.port, 
                ssl=ctx, 
                reuse_address=True, 
                ssl_handshake_timeout=3
            )
        except (PermissionError, OSError) as error:
            self.log.warning(f"{error}")
            return False

        self.log.info(f"Successfully started listener on {self.host}:{self.port}")

        return True

    async def start_listener(self) -> None:
        """Used to separate logic between server creation and server execution as we have to execute as a scheduled asyncio task to avoid blocking event loop"""
        async with self.server:
            await self.server.serve_forever()



