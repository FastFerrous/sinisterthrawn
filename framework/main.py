import asyncio
from tls.tls import Tls
from shell.shell import SessionManager


async def main():
    mgr = SessionManager()
    await mgr.manage()



if __name__ == "__main__":
    asyncio.run(main())


# setup argparse for logger level and that will be configured and setup globally for all resources 
