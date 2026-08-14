import asyncio
import logging
import argparse
from sys import stdout
from shell.SessionManager import SessionManager


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Framework")
    parser.add_argument(
        "-l",
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level (default: INFO)",
    )
    return parser.parse_args()


def setup_logger(level: str) -> logging.Logger:
    logger = logging.getLogger("framework")
    logger.setLevel(getattr(logging, level))

    handler = logging.StreamHandler(stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(funcName)s - %(message)s", datefmt="%H:%M:%S"
        )
    )
    logger.addHandler(handler)

    return logger


async def main():

    # parse log level and instantiate logger for application use
    args = parse_args()
    setup_logger(args.log_level)

    mgr = SessionManager()
    await mgr.manage()


if __name__ == "__main__":
    asyncio.run(main())

# need to create some kind of queue that tracks session manager logs when user is interactive with a session. these would be replayed post exit back to framework
# also track states really well between sessions, ie disconnection occurs, etc.
# change certs to local and remote. makes more sense than client/server in this instance -- so far needs changed in cert_gen.sh, patch.py and tls.py
