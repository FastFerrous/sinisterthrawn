import asyncio
import shlex
from uuid import uuid4
from enum import IntEnum
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

class ShellErrors(IntEnum):
    SUCCESS = (0,)
    INVALID_ARGS = (1,)

class Session:
    """Serves as entry point for interactively interacting with sessions"""

    def __init__(self, session_id: uuid4, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.name: str | None = None # will be used later to add custom names
        self.active : bool = True
        self.session_id : uuid4 = session_id
        self.reader : asyncio.StreamReader = reader
        self.writer : asyncio.StreamWriter = writer
        self.addr : tuple[str, int] = writer.get_extra_info("peername")
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
        ''' Serves as interactive REPL for remote session '''

        # local scope value for sessions as they go in and out of interactive states 
        is_running = True 

        # start repl 
        with patch_stdout():
            while is_running:
                try:
                    cmd = await self.prompt.prompt_async(f"{self.name}@{self.session_id}: ")
                except (EOFError, KeyboardInterrupt):
                    break

                if cmd is None or 0 == len(cmd):
                    continue

                try:
                    split_cmd = shlex.split(cmd)
                except ValueError:
                    continue

                if split_cmd[0] not in self.commands:
                    # logging invalid command
                    continue

                result = await self.commands[split_cmd[0]](split_cmd[1:])
                match result:
                    case ShellErrors.SUCCESS:
                        continue
                    case ShellErrors.INVALID_ARGS:
                        # logger here
                        # may swap this to catch only critical errors, since loggin can be done elsewehwere
                        continue

    async def get_process_list(self, args: list):
        # debug 
        if self.writer.is_closing():
            print("closing")

        self.writer.write(b'apples')

        try: 
            await self.writer.drain()
        except ConnectionResetError:
            print("connection has been reset")

        # await self.reader.read(size)
        # end debug 

        pass 

    async def get_netstat(self, args: list):
        pass 

    async def get_listing(self, args: list):
        pass 

    async def background_session(self, _):
        pass 

    async def exit(self, _):
        pass 

