"""SSH-приманка на asyncssh. Принимает пароль после нескольких попыток,
отдаёт поддельную оболочку и пишет всё в SQLite."""
import asyncio
import os
import sqlite3
from collections import Counter
from typing import Any

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
READ_CHUNK = 1024
PRUNE_INTERVAL = 3600


class Honeypot:
    def __init__(self, store: Store, hostname="srv04", accept_after=2, max_connections=100, max_per_ip=5):
        self.store = store
        self.hostname = hostname
        self.accept_after = accept_after
        self.max_connections = max_connections
        self.max_per_ip = max_per_ip
        self.sessions: dict = {}
        self.active = 0
        self.per_ip: Counter = Counter()
        self.rejected = 0
        self.prune_task: asyncio.Task | None = None

    def admit(self, ip):
        """Пускает ли соединение: общий лимит и лимит на один адрес защищают от заливания ловушки."""
        if self.active >= self.max_connections or self.per_ip[ip] >= self.max_per_ip:
            self.rejected += 1
            return False
        self.active += 1
        self.per_ip[ip] += 1
        return True

    def release(self, ip):
        self.active = max(0, self.active - 1)
        self.per_ip[ip] -= 1
        if self.per_ip[ip] <= 0:
            del self.per_ip[ip]

    async def prune_loop(self, max_sessions, max_age_days):
        while True:
            try:
                self.store.prune(max_sessions, max_age_days)
            except sqlite3.ProgrammingError:
                return  # база закрыта вместе с сервером
            await asyncio.sleep(PRUNE_INTERVAL)

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
            process.stdout.write(self._crlf(shell.run_line(command[:MAX_LINE])))
            return
        process.stdout.write(BANNER + MOTD.format(host=shell.hostname))
        while not shell.exit_requested:
            process.stdout.write(shell.prompt)
            try:
                line = await asyncio.wait_for(self._readline(process), IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                return
            if not line:
                return
            process.stdout.write(self._crlf(shell.run_line(line[:MAX_LINE])))
        process.stdout.write("logout\r\n")

    @staticmethod
    async def _readline(process):
        """Читает строку с потолком по размеру. Пустая строка означает конец ввода или слишком длинный ввод без перевода строки."""
        buf = ""
        while "\n" not in buf:
            chunk = await process.stdin.read(READ_CHUNK)
            if not chunk:
                return buf
            buf += chunk
            if len(buf) > MAX_LINE * 4:
                return ""
        return buf

    @staticmethod
    def _crlf(text):
        return text.replace("\r\n", "\n").replace("\n", "\r\n")


class HoneyServer(asyncssh.SSHServer):
    def __init__(self, pot):
        self.pot = pot
        self.conn = None
        self.session_id = None
        self.attempts = 0
        self.ip = None

    def connection_made(self, conn):
        self.conn = conn
        host, port = conn.get_extra_info("peername")[:2]
        if not self.pot.admit(host):
            conn.abort()
            return
        self.ip = host
        self.session_id = self.pot.store.open_session(host, port)
        self.pot.sessions[conn] = self.session_id

    def connection_lost(self, exc):
        if self.ip is not None:
            self.pot.release(self.ip)
        self.pot.sessions.pop(self.conn, None)
        if self.session_id is not None:
            if exc is not None:
                self.pot.store.event(self.session_id, "disconnect", {"error": str(exc)})
            self.pot.store.close_session(self.session_id)

    def begin_auth(self, username):
        version = self.conn.get_extra_info("client_version") if self.conn is not None else None
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


async def start(host, port, db_path, key_path, hostname="srv04", accept_after=2,
                max_connections=100, max_per_ip=5, max_sessions=50000, max_age_days=30):
    store = Store(db_path)
    store.prune(max_sessions, max_age_days)
    pot = Honeypot(store, hostname=hostname, accept_after=accept_after, max_connections=max_connections, max_per_ip=max_per_ip)
    server = await asyncssh.listen(
        host,
        port,
        server_factory=pot.server_factory,
        server_host_keys=[load_host_key(key_path)],
        process_factory=pot.handle_process,
        server_version="OpenSSH_9.2p1 Debian-2+deb12u2",
        login_timeout=30,
        encoding="utf-8",
        max_line_length=MAX_LINE,
    )
    acceptor: Any = server  # asyncssh не объявляет этот атрибут; тесты и CLI читают счётчики через него
    acceptor.pot = pot
    pot.prune_task = asyncio.create_task(pot.prune_loop(max_sessions, max_age_days))
    return server, store
