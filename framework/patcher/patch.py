import argparse
import logging 
from typing import Optional
from pathlib import Path
from ipaddress import IPv4Address

log = logging.getLogger("framework")

def parse_stamper_args(args: list, str_usage:str) -> Optional[argparse.Namespace]: 
    ''' parses required arguments for stamping sinister thrawn binary '''

    parser = argparse.ArgumentParser(
        prog="stamp",
        usage=str_usage,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        exit_on_error=False,
        color=False,
    )

    # configuration modes
    parser.add_argument("-l", "--listen", required=False, type=IPv4Address, default=IPv4Address("0.0.0.0"), help="remote bind address")
    parser.add_argument("-c", "--callback", required=False, type=str, help="callback address or domain")
    parser.add_argument("--sleep", type=int, required=False, default=10, help="seconds before initial connection or bind is attempted")

    # port is used in either callback or listen mode, reducing to single arg
    parser.add_argument("-p", "--port", required=True, type=int, help="bind or callback port")

    # certs should be permitted for client and server auth, or different certs will be required for listen/callback modes. cert_gen has both modes
    parser.add_argument("--certs", type=Path, required=True, help="directory with required certificates")

    # callback specific args
    parser.add_argument("-s", "--sni", type=str, required=False, help="SNI presented during certificate exchange")
    parser.add_argument("-i", "--interval", type=int, required=False, help="Minutes between callback iterations", default=240)
    parser.add_argument("-m", "--max", type=int, required=False, help="Number of callbacks permitted before process termination", default=3)

    try:
        parsed_args = parser.parse_args(args)
    except argparse.ArgumentError as error:
        log.info(f"{error}")
        return None

    except SystemExit:
        return None

    if parsed_args.callback and parsed_args.listen != IPv4Address("0.0.0.0"):
        log.info("stamped binary must have only one specified mode, ie --callback or --listen")
        return None

    if not 1 <= parsed_args.port <= 65535:
        log.info(f"port {parsed_args.port} out of range [1-65535]")
        return None

    if not 10 <= parsed_args.sleep <= 60:
        log.info(f"sleep time {parsed_args.sleep} out of range [10 - 60]")
        return None

    if not parsed_args.certs.exists() or not parsed_args.certs.is_dir():
        log.info(f"{parsed_args.certs} is not a valid directory")
        return None

    if parsed_args.callback:
        if len(parsed_args.callback) > 255:
            log.info(f"{parsed_args.callback} exceeds maximum length of 255")
            return None

        if not parsed_args.sni:
            parsed_args.sni = parsed_args.callback
        elif len(parsed_args.sni) > 255:
            log.info(f"{parsed_args.sni} exceeds maximum length of 255")
            return None 

        if not 5 <= parsed_args.interval <= 1440: 
            log.info(f"interval {parsed_args.interval} out of range [5-1440]")
            return None

        if not 3 <= parsed_args.max <= 30: 
            log.info(f"maximum number of callbacks {parsed_args.max} out of range [3-30]")
            return None

    return parsed_args

# required: address, port, certs, sleep, spki hash
