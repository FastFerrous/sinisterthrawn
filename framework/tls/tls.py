import ssl
import socket
from enum import IntEnum


class Mode(IntEnum):
    SERVER = (0,)
    CLIENT = 1


class Tls:
    """Serves as single entrypoint for tls operations, provides both server and client modes"""

    def __init__(self, address: str, port: int, mode: bool):
        self.host: str = address
        self.port: int = port
        self.mode: Mode = Mode.SERVER if mode else Mode.CLIENT

    def listen(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain("certs/cert.pem", "certs/key.pem")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(1)
            print(f"Listening on {self.host}:{self.port}")

            with ctx.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
                with conn:
                    print(f"Connection from {addr}")
                    try:
                        data = conn.recv(4096)
                    except Exception:
                        print("eh")
                        return

                    print(f"Received: {data}")
                    conn.sendall(b"Hello from server\n")
                    print("Response sent, closing")


# need to take in all requirements, address, port, certs, mode, etc. if client, it needs the server cert
