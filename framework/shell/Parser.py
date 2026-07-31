import argparse
from ipaddress import IPv4Address
from pathlib import Path
from typing import Optional


def parse_listen_args(args: list) -> Optional[argparse.Namespace]:
    """Parses user supplied listen `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="listen",
        usage="listen [-b <address>] [-p <port>] --certs <cert dir>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-b",
        "--bind",
        default="0.0.0.0",
        required=False,
        type=IPv4Address,
        help="bind address",
    )
    parser.add_argument(
        "-p", "--port", default=443, type=int, required=False, help="bind port"
    )
    parser.add_argument(
        "--certs", type=Path, required=True, help="directory with required certificates"
    )

    try:
        parsed_args = parser.parse_args(args)
    except (SystemExit, argparse.ArgumentError):
        return None

    if not 1 <= parsed_args.port <= 65535:
        return None

    if not parsed_args.certs.exists() or not parsed_args.certs.is_dir():
        return None

    return parsed_args

def parse_kill_listener_args(args: list) -> Optional[argparse.Namespace]:
    """Parses user supplied `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="kill_listener",
        usage="kill_listener --index <num>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-i", "--index", type=int, required=True, help="index of listener entry"
    )

    try:
        parsed_args = parser.parse_args(args)
    except (SystemExit, argparse.ArgumentError) as e:
        print(e)
        return None

    return parsed_args

def parse_interact_args(args: list) -> Optional[argparse.Namespace]:
    """Parses user supplied `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="interact",
        usage="kill_listener --index <num>",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-i", "--index", type=int, required=True, help="index of listener entry"
    )

    try:
        parsed_args = parser.parse_args(args)
    except (SystemExit, argparse.ArgumentError) as e:
        print(e)
        return None

    return parsed_args


# certs will be the path, we have the server key and cert, client key and cert and then the ca. uses ca to validate the client.
