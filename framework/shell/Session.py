import asyncio
import shlex
import logging
from uuid import uuid4
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from shell.commands.netstat import Netstat


class Session:
    """Serves as entry point for interactively interacting with sessions"""

    def __init__(
        self,
        session_id: uuid4,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self.name: str | None = None  # will be used later to add custom names
        self.session_id: uuid4 = session_id
        self.is_active: bool = False
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.addr: tuple[str, int] = writer.get_extra_info("peername")
        self.log: logging.Logger = logging.getLogger("framework")
        self.commands: dict = {
            "ps": self.get_process_list,
            "netstat": self.get_netstat,
            "ls": self.get_listing,
            "background": self.background_session,
            "exit": self.exit,
        }
        self.prompt: PromptSession = PromptSession(
            completer=WordCompleter(sorted(self.commands), sentence=True),
            history=InMemoryHistory(),
            complete_while_typing=False,
        )

    async def run(self):
        """Serves as interactive REPL for remote session"""

        # reset due to nature of flipping boolean for interacting with sessions
        self.is_active = True

        # start repl
        with patch_stdout():
            while self.is_active:
                try:
                    cmd = await self.prompt.prompt_async(
                        f"{self.name}@{self.session_id}: "
                    )
                except (EOFError, KeyboardInterrupt):
                    await self.background_session(None)
                    continue

                if cmd is None or 0 == len(cmd):
                    continue

                try:
                    split_cmd = shlex.split(cmd)
                except ValueError as format_error:
                    self.log.info(format_error)
                    continue

                if split_cmd[0] not in self.commands:
                    self.log.info(
                        f"{split_cmd[0]} is an invalid command within remote session"
                    )
                    continue

                await self.commands[split_cmd[0]](split_cmd[1:])

    async def get_process_list(self, _):
        pass 

    async def get_netstat(self, _):
        """Performs `ss -tunap` equivalent on remote host. `inet_diag, tcp_diag, udp_diag` kernel modules be loaded depending on kernel and configuration on remote host"""

        if self.writer.is_closing():
            return None 

        # will call proto write with opcode and None as data 
        # then will await proto recv 
        # if additioanl data, loop until proto recv is finished. then prtin the connections, etc. 

        ns = Netstat()
        request = ns.pack_request()
        if request is None: 
            self.log.info("Unable to create `netstat` request")
            return 

        self.writer.write(request)

        try:
            await self.writer.drain()
        except ConnectionResetError:
            return None 

        response = await self.reader.read() ## should store helpers inside of the proto.c file


    async def get_listing(self, args: list):
        pass

    async def background_session(self, _) -> None:
        self.log.debug(f"Backgrounding session: {self.session_id}")
        self.is_active = False

    async def exit(self, _):
        pass


# need a way of returning critical errors back to the framework, ie if a session has encountered a critical problem that needs to be shutdown, etc. 
    # most likely just bubble up a status error back so that run returns with a status that can be tracked
    # await that is called within run needs to return some form of shell status, etc. that canbe bubbled up, will add once done with a bit more framework managment