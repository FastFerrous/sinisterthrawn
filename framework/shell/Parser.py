import argparse
import logging
from ipaddress import IPv4Address
from pathlib import Path
from typing import Optional

log = logging.getLogger("framework")


def parse_listen_args(args: list, help_str: str) -> Optional[argparse.Namespace]:
    """Parses user supplied listen `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="listen",
        usage=help_str,
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
    except argparse.ArgumentError as error:
        log.info(f"{error}")
        return None

    except SystemExit:
        return None

    if not 1 <= parsed_args.port <= 65535:
        log.info(f"port {parsed_args.port} out of range [1-65535]")
        return None

    if not parsed_args.certs.exists() or not parsed_args.certs.is_dir():
        log.info(f"{parsed_args.certs} is not a valid directory")
        return None

    return parsed_args


def parse_kill_listener_args(args: list, help_str: str) -> Optional[argparse.Namespace]:
    """Parses user supplied `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="kill_listener",
        usage=help_str,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-i", "--index", type=int, required=True, help="index of listener entry"
    )

    try:
        parsed_args = parser.parse_args(args)
    except argparse.ArgumentError as error:
        log.info(f"{error}")
        return None

    except SystemExit:
        return None

    return parsed_args


def parse_interact_args(args: list, help_str: str) -> Optional[argparse.Namespace]:
    """Parses user supplied `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="interact",
        usage=help_str,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-i", "--index", type=int, required=True, help="index of listener entry"
    )

    try:
        parsed_args = parser.parse_args(args)
    except argparse.ArgumentError as error:
        log.info(f"{error}")
        return None

    except SystemExit:
        return None

    return parsed_args


def parse_kill_session_args(args: list, help_str: str) -> Optional[argparse.Namespace]:
    """Parses user supplied `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="kill_session",
        usage=help_str,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-i", "--index", type=int, required=True, help="index of session entry"
    )

    try:
        parsed_args = parser.parse_args(args)
    except argparse.ArgumentError as error:
        log.info(f"{error}")
        return None

    except SystemExit:
        return None

    return parsed_args


def parse_connect_args(args: list, help_str: str) -> Optional[argparse.Namespace]:
    """Parses user supplied listen `args` and returns namespace on success or None on error"""

    parser = argparse.ArgumentParser(
        prog="connect",
        usage=help_str,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        type=IPv4Address,
        help="remote address",
    )
    parser.add_argument("-p", "--port", type=int, required=True, help="remote port")
    parser.add_argument(
        "-t", "--timeout", type=int, default=5, required=True, help="connection timeout"
    )
    parser.add_argument(
        "--certs", type=Path, required=True, help="directory with required certificates"
    )

    try:
        parsed_args = parser.parse_args(args)
    except argparse.ArgumentError as error:
        log.info(f"{error}")
        return None

    except SystemExit:
        return None

    if not 1 <= parsed_args.port <= 65535:
        log.info(f"port {parsed_args.port} out of range [1-65535]")
        return None

    if not parsed_args.certs.exists() or not parsed_args.certs.is_dir():
        log.info(f"{parsed_args.certs} is not a valid directory")
        return None

    if not 1 <= parsed_args.timeout <= 30:
        log.info(f"timeout {parsed_args.timeout} out of range [1-30]")
        return None

    return parsed_args
