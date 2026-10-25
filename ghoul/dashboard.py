"""Локальный дашборд: JSON API поверх SQLite и одна статическая страница."""
import json
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .store import Store

INDEX = Path(__file__).with_name("dashboard.html")
HOUR = 3600
TOP_LIMIT = 12


def summary(store):
    db = store.db
    one = lambda sql: db.execute(sql).fetchone()[0]
    return {
        "sessions": one("SELECT COUNT(*) FROM sessions"),
        "authed": one("SELECT COUNT(*) FROM sessions WHERE authed = 1"),
        "ips": one("SELECT COUNT(DISTINCT src_ip) FROM sessions"),
        "commands": one("SELECT COUNT(*) FROM events WHERE kind = 'command'"),
        "urls": one("SELECT COUNT(DISTINCT json_extract(data, '$.url')) FROM events WHERE kind = 'url'"),
        "last": db.execute("SELECT MAX(started) FROM sessions").fetchone()[0],
        "now": time.time(),
    }


def top(store, what):
    if what == "ips":
        rows = store.db.execute(
            "SELECT src_ip, COUNT(*) c FROM sessions GROUP BY src_ip ORDER BY c DESC LIMIT ?", (TOP_LIMIT,)
        ).fetchall()
        return [[r[0], r[1]] for r in rows]
    if what == "clients":
        rows = store.db.execute(
            "SELECT client_version, COUNT(*) c FROM sessions WHERE client_version IS NOT NULL "
            "GROUP BY client_version ORDER BY c DESC LIMIT ?",
            (TOP_LIMIT,),
        ).fetchall()
        return [[r[0], r[1]] for r in rows]
    kinds = {
        "creds": ("auth", lambda d: f"{d['username']}:{d['password']}"),
        "users": ("auth", lambda d: d["username"]),
        "cmds": ("command", lambda d: d["cmd"]),
        "urls": ("url", lambda d: d["url"]),
    }
    if what not in kinds:
        return None
    kind, fmt = kinds[what]
    counter = Counter(fmt(d) for _, _, d in store.events(kind))
    return [[k, v] for k, v in counter.most_common(TOP_LIMIT)]


def timeline(store, hours=48):
    now = time.time()
    start = (int(now) // HOUR - hours + 1) * HOUR
    buckets = [{"t": start + i * HOUR, "n": 0, "authed": 0} for i in range(hours)]
    rows = store.db.execute("SELECT started, authed FROM sessions WHERE started >= ?", (start,))
    for started, authed in rows:
        b = buckets[min(int((started - start) // HOUR), hours - 1)]
        b["n"] += 1
        b["authed"] += authed
    return buckets


def sessions(store, limit=40):
    rows = store.db.execute(
        "SELECT s.id, s.started, s.ended, s.src_ip, s.client_version, s.username, s.authed, "
        "(SELECT COUNT(*) FROM events e WHERE e.session_id = s.id AND e.kind = 'command') AS cmds "
        "FROM sessions s ORDER BY s.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def session_events(store, session_id):
    rows = store.db.execute(
        "SELECT ts, kind, data FROM events WHERE session_id = ? ORDER BY id", (session_id,)
    ).fetchall()
    return [{"ts": r["ts"], "kind": r["kind"], "data": json.loads(r["data"])} for r in rows]


ATTACK_RULES = [
    ("загрузчик ботнета", ("wget http", "curl -s http", "curl http", "| sh", "tftp", "ftpget")),
    ("захват аккаунта", ("chpasswd", "passwd")),
    ("кража ssh-ключей", (".ssh", "authorized_keys")),
    ("разведка системы", ("uname", "whoami", "cat /etc/passwd", "cpuinfo", "free", "nproc", "ifconfig", "id", "uptime", "df", "ls", "ps", "w")),
]


def classify(commands):
    """Тип атаки по набору команд сессии: первое правило, под которое что-то подошло."""
    joined = " ; ".join(commands)
    for label, needles in ATTACK_RULES[:-1]:
        if any(n in joined for n in needles):
            return label
    first = [c.split()[0] for c in commands if c.split()]
    if any(c in ("uname", "whoami", "id", "cat", "free", "nproc", "ifconfig", "uptime", "df", "ls", "ps", "w") for c in first):
        return ATTACK_RULES[-1][0]
    return "прочее"


def attacks(store):
    per_session = {}
    for sid, _, d in store.events("command"):
        per_session.setdefault(sid, []).append(d["cmd"])
    counter = Counter(classify(cmds) for cmds in per_session.values())
    silent = store.db.execute("SELECT COUNT(*) FROM sessions WHERE authed = 1").fetchone()[0] - len(per_session)
    if silent > 0:
        counter["вошёл и молчит"] += silent
    return [[k, v] for k, v in counter.most_common()]


def feed(store, limit=12):
    rows = store.db.execute(
        "SELECT e.ts, e.kind, e.data, s.src_ip FROM events e JOIN sessions s ON s.id = e.session_id "
        "WHERE e.kind IN ('auth', 'command', 'url') ORDER BY e.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    out = []
    for r in rows:
        d = json.loads(r["data"])
        if r["kind"] == "auth":
            text = f"{d['username']}:{d['password']} -> " + ("вход" if d["ok"] else "отказ")
        elif r["kind"] == "command":
            text = d["cmd"]
        else:
            text = d["url"]
        out.append({"ts": r["ts"], "ip": r["src_ip"], "kind": r["kind"], "text": text})
    return out


def route(store, path, query):
    if path == "/api/summary":
        return summary(store)
    if path == "/api/top":
        return top(store, query.get("kind", [""])[0])
    if path == "/api/timeline":
        return timeline(store)
    if path == "/api/attacks":
        return attacks(store)
    if path == "/api/feed":
        return feed(store)
    if path == "/api/sessions":
        return sessions(store)
    if path.startswith("/api/session/"):
        tail = path.rsplit("/", 1)[-1]
        return session_events(store, int(tail)) if tail.isdigit() else None
    return None


def make_handler(db_path):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            if url.path.startswith("/api/"):
                store = Store(db_path)
                try:
                    data = route(store, url.path, parse_qs(url.query))
                finally:
                    store.close()
                if data is None:
                    return self._send(404, b'{"error":"not found"}', "application/json")
                return self._send(200, json.dumps(data, ensure_ascii=False).encode(), "application/json")
            self._send(404, b"not found", "text/plain")

        def log_message(self, *args):
            pass

    return Handler


def serve(host, port, db_path):
    Store(db_path).close()  # создать базу и схему, если их ещё нет
    httpd = ThreadingHTTPServer((host, port), make_handler(db_path))
    print(f"дашборд: http://{host}:{port}  (база {db_path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
