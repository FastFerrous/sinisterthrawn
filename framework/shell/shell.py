import shlex
import asyncio
from enum import IntEnum
from uuid import uuid4
from dataclasses import dataclass
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

from tls.tls import Tls, Mode
from shell.parser import parse_listen_args, parse_kill_listener_args


@dataclass
class ListenerEntry: 
    ''' Wraps asyncio task as well as tls instance for each listener session '''
    task: asyncio.Task
    tls: Tls

class SessionManagerErrors(IntEnum):
    SUCCESS = (0,)
    INVALID_ARGS = 1, 
    UNABLE_TO_LISTEN = 2, 
    NO_ACTIVE_LISTENERS = 3

class SessionManager:
    """Serves as single point of entry to the framework and performs management of all remote sessions"""

    def __init__(self):
        self.is_running: bool = True
        self.listeners: dict[uuid4, ListenerEntry] = {}
        self.commands: dict = {
            "exit": self.exit,
            "listen": self.listen,
            "kill_listener": self.kill_listener,
            "connect": self.connect,
            "kill_session": self.kill_session,
            "show_listeners": self.show_listeners,
            "show_sessions": self.show_sessions,
            "interact": self.interact,
        }
        self.session: PromptSession = PromptSession(
            completer=WordCompleter(sorted(self.commands), sentence=True),
            history=InMemoryHistory(),
            complete_while_typing=False,
        )

    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ''' Callback leveraged from asyncio server on accepted client connections '''
        addr = writer.get_extra_info("peername")
        # logger printing that an inbound connection was established from {addr}

        # create sub prompt toolkit instance, store reader and writer and then add to sessions
        # this will then allow us to go "interactive" with that session and have our reader/writer
        # ensure we do proper handling of the reader and writer object ie await writer.close(), etc. 

        # once we register those into the class, do we need to do anything here to keep it alive since or if this function returns they go out of scope?
        # most likely need to keep alive
        # best way to keep alive, while loop that continues until its set to inactive? just perform some asyncio sleeps? 
        # once not active, delete from sessions and await close()

    async def manage(self) -> None:
        with patch_stdout():
            while self.is_running:
                try:
                    cmd = await self.session.prompt_async(">>> ")
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
                    case SessionManagerErrors.SUCCESS:
                        continue 
                    case SessionManagerErrors.INVALID_ARGS:
                        # logger here 
                        # may swap this to catch only critical errors, since loggin can be done elsewehwere
                        continue 

    async def listen(self, args: list) -> SessionManagerErrors:
        ''' Uses supplied values to craft a Tls `listener` that awaits inbound connections '''

        # validate args length is non zero and then pass to argparse 
        if len(args) == 0:
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_listen_args(args)
        if parsed_args is None:
            return SessionManagerErrors.INVALID_ARGS

        # create tls listener, check whether an immediate error has occured during setup and if not, create background async task and store into listeners dict
        listener = Tls(parsed_args.bind, parsed_args.port, parsed_args.certs, Mode.SERVER)
        if not await listener.create_listener(self._on_connect):
            return SessionManagerErrors.UNABLE_TO_LISTEN

        task = asyncio.create_task(listener.start_listener())
        task_id = uuid4()

        self.listeners[task_id] = ListenerEntry(task=task, tls=listener)

        return SessionManagerErrors.SUCCESS        

    async def show_listeners(self, _) -> SessionManagerErrors:
        # todo: log print if none
        if not self.listeners:
            return SessionManagerErrors.NO_ACTIVE_LISTENERS

        for idx, (_, entry) in enumerate(self.listeners.items()):
            for sock in entry.tls.server.sockets:
                addr = sock.getsockname()
                print(f"[{idx}] -- Local Address:{addr[0]} Local Port:{addr[1]}")

        return SessionManagerErrors.SUCCESS
        
    async def kill_listener(self, args: list) -> SessionManagerErrors:
        """Cancels the current running asyncio task for specified listener session and awaits server closure"""

        # parse the required args for cancelling listener sessions
        if len(args) == 0:
            #todo: logging
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_kill_listener_args(args)
        if parsed_args is None: 
            #todo: logging
            return SessionManagerErrors.INVALID_ARGS

        # attempt to validate that the index exists within the stored dict and if so, pop the entry
        try: 
            listener_uuid = list(self.listeners.keys())[parsed_args.index]
            entry = self.listeners.pop(listener_uuid)
        except IndexError:
            return SessionManagerErrors.INVALID_ARGS

        # close down the server and await for any pending connections to complete before cancelling the asyncio task
        entry.tls.server.close()
        await entry.tls.server.wait_closed()
        entry.task.cancel()

        return SessionManagerErrors.SUCCESS


    





    async def connect(self, args):
        """connect <host> <port>"""
        if len(args) < 2:
            print("usage: connect <host> <port>")
            return

        host, port = args[0], int(args[1])
        reader, writer = await asyncio.open_connection(host, port)
        self._session_id += 1
        sid = self._session_id
        self.sessions[sid] = writer
        print(f"[+] session {sid} connected to {host}:{port}")

    async def kill_session(self, args):
        """kill_session <id>"""
        if not args:
            print("usage: kill_session <id>")
            return

        sid = int(args[0])
        writer = self.sessions.pop(sid, None)
        if writer:
            writer.close()
            await writer.wait_closed()
            print(f"[-] session {sid} closed")
        else:
            print(f"no session with id {sid}")

    async def show_sessions(self, args):
        if not self.sessions:
            print("no active sessions")
            return
        for sid, writer in self.sessions.items():
            peer = writer.get_extra_info("peername", ("?", "?"))
            print(f"  {sid}  {peer[0]}:{peer[1]}")

    async def interact(self, args):
        if not self.sessions:
            print("no active sessions")
            return
        for sid, writer in self.sessions.items():
            peer = writer.get_extra_info("peername", ("?", "?"))
            print(f"  {sid}  {peer[0]}:{peer[1]}")

    async def exit(self, args):
        for writer in self.sessions.values():
            writer.close()
        for server in self.listeners.values():
            server.close()
        self.is_running = False


# todo: inside manage(), double check all try/excepts for actual correct error handling
# todo: add logger() prints depending on debug level, ie most will be info. so as you run the cli, you get info prints
# todo: on_connect may need to be on_accept, we will need to see when we start doing the alternate
