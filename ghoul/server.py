"""SSH-приманка на asyncssh. Принимает пароль после нескольких попыток,
отдаёт поддельную оболочку и пишет всё в SQLite."""
import asyncio
import os

import asyncssh

from .shell import Shell
from .store import Store

BANNER = "Debian GNU/Linux 12\r\n"
MOTD = (
    "Linux {host} 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 x86_64\r\n\r\n"
    "Last login: Thu Feb  1 02:58:41 2024 from 10.0.2.2\r\n"
)
IDLE_TIMEOUT = 120
MAX_SESSION_SECONDS = 600
MAX_LINE = 4096


class Honeypot:
    def __init__(self, store: Store, hostname="srv04", accept_after=2):
        self.store = store
        self.hostname = hostname
        self.accept_after = accept_after
        self.sessions = {}

    def server_factory(self):
        return HoneyServer(self)

    async def handle_process(self, process):
        conn = process.channel.get_connection()
        session_id = self.sessions.get(conn)
        if session_id is None:
            process.exit(1)
            return
        shell = Shell(self.hostname, on_event=lambda kind, data: self.store.event(session_id, kind, data))
        try:
            await asyncio.wait_for(self._interact(process, shell), MAX_SESSION_SECONDS)
        except asyncio.TimeoutError:
            self.store.event(session_id, "timeout", {})
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, asyncssh.SignalReceived):
            pass
        finally:
            process.exit(0)

    async def _interact(self, process, shell):
        command = process.command
        if command is not None:
            process.stdout.write(self._crlf(shell.run_line(command)))
            return
        process.stdout.write(BANNER + MOTD.format(host=shell.hostname))
        while not shell.exit_requested:
            process.stdout.write(shell.prompt)
            try:
                line = await asyncio.wait_for(process.stdin.readline(), IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                return
            if not line:
                return
            process.stdout.write(self._crlf(shell.run_line(line[:MAX_LINE])))
        process.stdout.write("logout\r\n")

    @staticmethod
    def _crlf(text):
        return text.replace("\r\n", "\n").replace("\n", "\r\n")


class HoneyServer(asyncssh.SSHServer):
    def __init__(self, pot):
        self.pot = pot
        self.conn = None
        self.session_id = None
        self.attempts = 0

    def connection_made(self, conn):
        self.conn = conn
        host, port = conn.get_extra_info("peername")[:2]
        self.session_id = self.pot.store.open_session(host, port)
        self.pot.sessions[conn] = self.session_id

    def connection_lost(self, exc):
        self.pot.sessions.pop(self.conn, None)
        if self.session_id is not None:
            if exc is not None:
                self.pot.store.event(self.session_id, "disconnect", {"error": str(exc)})
            self.pot.store.close_session(self.session_id)

    def begin_auth(self, username):
        version = self.conn.get_extra_info("client_version")
        if version:
            self.pot.store.set_client_version(self.session_id, version)
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.attempts += 1
        ok = self.attempts > self.pot.accept_after and bool(password)
        self.pot.store.log_auth(self.session_id, username, password, ok)
        return ok

    def public_key_auth_supported(self):
        return False


def load_host_key(path):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(path)
        os.chmod(path, 0o600)
    return asyncssh.read_private_key(path)


async def start(host, port, db_path, key_path, hostname="srv04", accept_after=2):
    store = Store(db_path)
    pot = Honeypot(store, hostname=hostname, accept_after=accept_after)
    server = await asyncssh.listen(
        host,
        port,
        server_factory=pot.server_factory,
        server_host_keys=[load_host_key(key_path)],
        process_factory=pot.handle_process,
        server_version="OpenSSH_9.2p1 Debian-2+deb12u2",
        login_timeout=30,
        encoding="utf-8",
    )
    return server, store
