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
                f"{self.certs}/svr_crt.pem", f"{self.certs}/svr_key.pem"
            )
        except FileNotFoundError as error:
            self.log.warning(f"{error}")
            return False

        try:
            self.server = await asyncio.start_server(
                on_connect_cb, str(self.host), self.port, ssl=ctx
            )
        except (PermissionError, OSError) as error:
            self.log.warning(f"{error}")
            return False

        self.log.info(f"Successfully started listener on {self.host}:{self.port}")

        return True

    async def start_listener(self) -> None:
        """Used to separate logic between create and start so that caller can execute as a background asyncio task"""

        async with self.server:
            await self.server.serve_forever()




# need to modify to include ca cert since it uses that, so need server key, server crt, ca -- server.key, server.crt, ca.crt
# handle errors, need to be more verbose once dirty code is done

# listen -p 4443 --certs /opt/sinisterthrawn/framework/certs
