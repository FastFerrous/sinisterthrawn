import shlex
import asyncio
import logging
from enum import IntEnum
from uuid import uuid4
from dataclasses import dataclass
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

from tls.tls import Tls, Mode
from shell.Session import Session
from shell.Parser import parse_listen_args, parse_kill_listener_args, parse_interact_args, parse_kill_session_args


@dataclass
class ListenerEntry:
    """Wraps asyncio task as well as tls instance for each listener session"""
    task: asyncio.Task
    tls: Tls


class SessionManagerErrors(IntEnum):
    SUCCESS = (0,)
    INVALID_ARGS = (1,)
    UNABLE_TO_LISTEN = (2,)
    NO_ACTIVE_LISTENERS = 3, 
    NO_ACTIVE_SESSIONS = 4 


class SessionManager:
    """Serves as single point of entry to the framework and performs management of all remote sessions"""

    def __init__(self):
        self.is_running: bool = True
        self.listeners: dict[uuid4, ListenerEntry] = {}
        self.sessions: dict[uuid4, Session] = {}
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

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # todo: log printing that an inbound connection was established from {writer.get_extra_info("peername")}

        session = Session(uuid4(), reader, writer)
        self.sessions[session.session_id] = session

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
        """Uses supplied values to craft a Tls `listener` that awaits inbound connections"""

        # validate args length is non zero and then pass to argparse
        if len(args) == 0:
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_listen_args(args)
        if parsed_args is None:
            return SessionManagerErrors.INVALID_ARGS

        # create tls listener, check whether an immediate error has occured during setup and if not, create background async task and store into listeners dict
        listener = Tls(
            parsed_args.bind, parsed_args.port, parsed_args.certs, Mode.SERVER
        )
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
            # todo: logging
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_kill_listener_args(args)
        if parsed_args is None:
            # todo: logging
            return SessionManagerErrors.INVALID_ARGS

        # attempt to validate that the index exists within the stored dict and if so, pop the entry
        try:
            listener_uuid = list(self.listeners.keys())[parsed_args.index]
            entry = self.listeners.pop(listener_uuid)
        except IndexError:
            return SessionManagerErrors.INVALID_ARGS

        # close down the server and await for any pending connections to complete before cancelling the asyncio task
        entry.tls.server.close()

        try: 
            await asyncio.wait_for(entry.tls.server.wait_closed(), timeout=5)
        except asyncio.TimeoutError: 
            pass 

        entry.task.cancel()

        return SessionManagerErrors.SUCCESS

    async def interact(self, args: list) -> SessionManagerErrors:
        if not self.sessions:
            # log print
            return SessionManagerErrors.NO_ACTIVE_SESSIONS

        if len(args) == 0:
            # todo: logging
            return SessionManagerErrors.INVALID_ARGS
        
        # parse the required args for interacting with remote sessions
        parsed_args = parse_interact_args(args)
        if parsed_args is None:
            # todo: logging
            return SessionManagerErrors.INVALID_ARGS

        # attempt to validate supplied index and obtain handle to session
        try:
            sess_uuid = list(self.sessions.keys())[parsed_args.index]
            session = self.sessions[sess_uuid]
        except IndexError:
            return SessionManagerErrors.INVALID_ARGS

        # go interactive with specified session 
        await session.run()

        return SessionManagerErrors.SUCCESS

    async def show_sessions(self, _):
        if not self.sessions:
            #todo: log print
            return SessionManagerErrors.NO_ACTIVE_SESSIONS

        for idx, (sid, session) in enumerate(self.sessions.items()):
            print(f"[{idx}] {session.name} -- {sid} -- {session.addr[0]}:{session.addr[1]}")

        return SessionManagerErrors.SUCCESS

    async def kill_session(self, args: list) -> SessionManagerErrors:
        if not self.sessions:
            return SessionManagerErrors.NO_ACTIVE_SESSIONS
        
        if len(args) == 0:
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_kill_session_args(args)
        if parsed_args is None:
            return SessionManagerErrors.INVALID_ARGS

        try:
            sess_uid = list(self.sessions.keys())[parsed_args.index]
            session = self.sessions.pop(sess_uid)
        except IndexError:
            return SessionManagerErrors.INVALID_ARGS

        if session.writer:
            session.writer.close()

            try: 
                await asyncio.wait_for(session.writer.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, ConnectionResetError): 
                pass 

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

    async def exit(self, _):
        pass 


# todo: parse args can take logger object? rather than relying on global
# todo: (exit) create shutdown function that is used as a cleanup, closes all listners, closes all sessions (false and close()), gathres tasks and wait with timeout for task.cancel()
# todo: inside manage(), double check all try/excepts for actual correct error handling
