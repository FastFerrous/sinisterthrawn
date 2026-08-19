import ssl
import socket
import asyncio
import aiofiles
import logging
import hashlib
from pathlib import Path
from enum import IntEnum
from collections.abc import Callable
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


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

    async def _close_writer(self, writer: asyncio.StreamWriter) -> None:
        """helper function to await closure of writer stream object"""

        if writer:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, ConnectionResetError):
                self.log.warning("timeout while waiting for connection to close")

    async def create_listener(
        self,
        on_connect_cb: Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
    ) -> bool:
        """Creates asyncio listener and awaits inbound client connections"""

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        try:
            ctx.load_cert_chain(f"{self.certs}/server.crt", f"{self.certs}/server.key")

            ctx.load_verify_locations(f"{self.certs}/ca.crt")
            ctx.verify_mode = ssl.CERT_REQUIRED

        except (PermissionError, FileNotFoundError, ssl.SSLError) as error:
            self.log.warning(f"{error}")
            return False

        try:
            self.server = await asyncio.start_server(
                on_connect_cb,
                str(self.host),
                self.port,
                ssl=ctx,
                reuse_address=True,
                ssl_handshake_timeout=3,
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

    async def connect(
        self,
        timeout: int,
        on_connect_cb: Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
    ) -> None:
        """Attempt to connect to specified remote host and append to sessions via on_connect_cb"""

        # Disable CA chain and hostname verification, trust is established via SPKI pin validation during mTLS exchange
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            ctx.load_cert_chain(f"{self.certs}/server.crt", f"{self.certs}/server.key")

            async with aiofiles.open(f"{self.certs}/client.crt", "rb") as f:
                remote_cert = x509.load_pem_x509_certificate(await f.read())

            expected_spki = hashlib.sha256(
                remote_cert.public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
            ).digest()

        except (OSError, ssl.SSLError, ValueError) as error:
            self.log.warning(error)
            return None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(self.host), self.port, ssl=ctx),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            self.log.info("connection timed out")
            return None
        except (OSError, ssl.SSLError) as error:
            self.log.info(error)
            return None

        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                await self._close_writer(writer)
                return None

            der_cert = ssl_object.getpeercert(binary_form=True)
            if der_cert is None:
                await self._close_writer(writer)
                return None

            cert = x509.load_der_x509_certificate(der_cert)

            spki_bytes = cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            spki_hash = hashlib.sha256(spki_bytes).digest()

        except (ValueError, TypeError) as error:
            self.log.info(error)
            await self._close_writer(writer)
            return None

        if spki_hash != expected_spki:
            self.log.info(
                "Remote endpoint does not match expected SPKI hash, terminating connection"
            )
            await self._close_writer(writer)
            return None

        await on_connect_cb(reader, writer)
