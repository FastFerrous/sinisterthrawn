import shlex
import asyncio
from enum import IntEnum
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout

from tls.tls import Tls
from shell.parser import parse_listen


class SessionManagerErrors(IntEnum):
    SUCCESS = (0,)
    INVALID_COMMAND = (1,)
    INVALID_ARGS = 2


class SessionManager:
    """Serves as single point of entry to the framework and performs management of all remote sessions"""

    def __init__(self):
        self.is_running: bool = True
        # self.listeners: dict[int, asyncio.Server] = {}
        # self.sessions: dict[int, asyncio.StreamWriter] = {}
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

    async def manage(self):
        with patch_stdout():
            while self.is_running:
                try:
                    cmd = await self.session.prompt_async(">>> ")
                except (EOFError, KeyboardInterrupt):
                    break

                if 0 == len(cmd) or cmd is None:
                    continue

                try:
                    split_cmd = shlex.split(cmd)
                except ValueError:
                    break

                if split_cmd[0] not in self.commands:
                    # logging invalid command
                    continue

                result = await self.commands[split_cmd[0]](split_cmd[1:])
                match result: 
                    case SessionManagerErrors.SUCCESS:
                        continue 
                    case SessionManagerErrors.INVALID_COMMAND:
                        # logger here 
                        print("invalid args")
                        continue 


    async def listen(self, args: list) -> SessionManagerErrors:
        ''' Uses supplied values to craft a Tls `listener` that awaits inbound connections '''

        if len(args) == 0:
            return SessionManagerErrors.INVALID_COMMAND

        parse_listen(args)
        
        

        # server = await asyncio.start_server(self._on_connect, host, port)
        # self._listener_id += 1
        # lid = self._listener_id
        # self.listeners[lid] = server
        # print(f"[+] listener {lid} started on {host}:{port}")

    async def kill_listener(self, args):
        """kill_listener <id>"""
        if not args:
            print("usage: kill_listener <id>")
            return

        lid = int(args[0])
        server = self.listeners.pop(lid, None)
        if server:
            server.close()
            await server.wait_closed()
            print(f"[-] listener {lid} closed")
        else:
            print(f"no listener with id {lid}")

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

    async def show_listeners(self, args):
        if not self.listeners:
            print("no active listeners")
            return
        for lid, server in self.listeners.items():
            for sock in server.sockets:
                addr = sock.getsockname()
                print(f"  {lid}  {addr[0]}:{addr[1]}")

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
# todo: add logger() prints
