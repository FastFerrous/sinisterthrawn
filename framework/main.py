import asyncio
from tls.tls import Tls
from shell.shell import SessionManager


async def main():
    mgr = SessionManager()
    await mgr.manage()

    # tls = Tls("0.0.0.0", 4443, True)
    # tls.listen()


if __name__ == "__main__":
    asyncio.run(main())


# setup argparse, can be a listener or client, currently we will only build out server impl for now
# currently using the test certs, will be in arg parse, default to that location though. names must match svr_key, svr_cert, client_key, etc
# this will be passed in from interactive client session with repl

# tls class needs locked behind our cmd class. we are a framework that creates sessions and we can handle multiple sessions
# todo: create logging library that wraps the python logging library ( when running main, we supply a debug level )
