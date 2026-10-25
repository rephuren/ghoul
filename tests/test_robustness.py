import asyncio
import time

import asyncssh

from ghoul import server
from ghoul.store import MAX_EVENTS_PER_SESSION, MAX_FIELD_CHARS, Store


def connect(port, password="x"):
    return asyncssh.connect("127.0.0.1", port, username="root", password=password, known_hosts=None, public_key_auth=False)


async def start(tmp_path, **kw):
    kw.setdefault("accept_after", 0)
    srv, store = await server.start("127.0.0.1", 0, str(tmp_path / "t.db"), str(tmp_path / "key"), **kw)
    return srv, store, srv.sockets[0].getsockname()[1]


async def shutdown(srv):
    srv.close()
    await srv.wait_closed()


def test_long_fields_are_clipped(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    sid = store.open_session("203.0.113.1", 1)
    store.event(sid, "command", {"cmd": "A" * 50000})
    (_, _, data), = store.events("command")
    assert len(data["cmd"]) == MAX_FIELD_CHARS + 1


def test_events_per_session_are_capped(tmp_path):
    store = Store(str(tmp_path / "b.db"))
    sid = store.open_session("203.0.113.1", 1)
    for i in range(MAX_EVENTS_PER_SESSION + 500):
        store.event(sid, "command", {"cmd": str(i)})
    total = store.db.execute("SELECT COUNT(*) FROM events WHERE session_id = ?", (sid,)).fetchone()[0]
    assert total == MAX_EVENTS_PER_SESSION + 1  # плюс одна служебная запись о превышении
    assert [k for k, in store.db.execute("SELECT kind FROM events WHERE kind = 'event-limit'")] == ["event-limit"]


def test_prune_by_count_and_age(tmp_path):
    store = Store(str(tmp_path / "c.db"))
    for i in range(10):
        sid = store.open_session(f"203.0.113.{i}", i)
        store.event(sid, "command", {"cmd": "id"})
    assert store.prune(max_sessions=4, max_age_days=30) == 6
    assert store.db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 4
    assert store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4
    kept = [r[0] for r in store.db.execute("SELECT id FROM sessions ORDER BY id")]
    assert kept == [7, 8, 9, 10]  # остаются самые новые
    assert store.prune(max_sessions=100, max_age_days=1, now=time.time() + 5 * 86400) == 4
    assert store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_per_ip_limit_rejects_extra_connections(tmp_path):
    async def scenario():
        srv, store, port = await start(tmp_path, max_per_ip=1)
        first = await connect(port)
        rejected = False
        try:
            await asyncio.wait_for(connect(port), 10)
        except (asyncssh.Error, OSError):
            rejected = True
        still_alive = (await first.run("whoami", check=True)).stdout
        first.close()
        await first.wait_closed()
        await asyncio.sleep(0.2)
        counters = (srv.pot.active, dict(srv.pot.per_ip), srv.pot.rejected)
        await shutdown(srv)
        return rejected, still_alive, counters

    rejected, alive, (active, per_ip, rejects) = asyncio.run(scenario())
    assert rejected and alive.strip() == "root"
    assert rejects >= 1 and active == 0 and per_ip == {}


def test_global_limit_rejects_extra_connections(tmp_path):
    async def scenario():
        srv, _, port = await start(tmp_path, max_connections=1, max_per_ip=10)
        first = await connect(port)
        rejected = False
        try:
            await asyncio.wait_for(connect(port), 10)
        except (asyncssh.Error, OSError):
            rejected = True
        first.close()
        await first.wait_closed()
        await shutdown(srv)
        return rejected

    assert asyncio.run(scenario())


def test_broken_clients_do_not_break_server(tmp_path):
    async def raw(port, payload, hold=0.0):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        if payload:
            writer.write(payload)
            await writer.drain()
        await asyncio.sleep(hold)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    async def scenario():
        srv, store, port = await start(tmp_path)
        await raw(port, b"")                                    # открыл и сразу закрыл
        await raw(port, b"GET / HTTP/1.0\r\n\r\n", 0.1)         # HTTP вместо SSH
        await raw(port, b"SSH-2.0-partial", 0.1)                # баннер без перевода строки
        await raw(port, b"SSH-2.0-x\r\n" + b"\xff" * 200_000, 0.2)  # мусор после баннера
        await raw(port, b"\x00" * 70_000, 0.2)                  # огромный «баннер» без SSH
        async with await connect(port) as conn:
            out = (await conn.run("id", check=True)).stdout
        await asyncio.sleep(0.3)
        counters = (srv.pot.active, dict(srv.pot.per_ip))
        open_sessions = store.db.execute("SELECT COUNT(*) FROM sessions WHERE ended IS NULL").fetchone()[0]
        await shutdown(srv)
        return out, counters, open_sessions

    out, (active, per_ip), open_sessions = asyncio.run(scenario())
    assert "uid=0" in out
    assert active == 0 and per_ip == {}
    assert open_sessions == 0


def test_oversized_input_without_newline_ends_session(tmp_path):
    async def scenario():
        srv, store, port = await start(tmp_path)
        async with await connect(port) as conn:
            proc = await conn.create_process(term_type=None)
            await proc.stdout.readuntil("# ")
            proc.stdin.write("A" * 60_000)
            await asyncio.wait_for(proc.wait(), 15)
        await asyncio.sleep(0.2)
        n_open = store.db.execute("SELECT COUNT(*) FROM sessions WHERE ended IS NULL").fetchone()[0]
        await shutdown(srv)
        return n_open

    assert asyncio.run(scenario()) == 0
