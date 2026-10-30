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

    def one(sql):
        return db.execute(sql).fetchone()[0]

    return {
        "sessions": one("SELECT COUNT(*) FROM sessions"),
        "authed": one("SELECT COUNT(*) FROM sessions WHERE authed = 1"),
        "ips": one("SELECT COUNT(DISTINCT src_ip) FROM sessions"),
        "commands": one("SELECT COUNT(*) FROM events WHERE kind = 'command'"),
        "revshells": one("SELECT COUNT(*) FROM events WHERE kind = 'revshell'"),
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


MAX_LIMIT = 200


def clamp(value, low, high, default):
    """Число из строки запроса, зажатое в [low, high]; мусор даёт значение по умолчанию."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, n))


def like_escape(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def sessions(store, limit=40, offset=0, ip=None, attack=None):
    limit = clamp(limit, 1, MAX_LIMIT, 40)
    offset = clamp(offset, 0, 10**9, 0)
    where, args = [], []
    if ip:
        where.append("s.src_ip LIKE ? ESCAPE '\\'")
        args.append(like_escape(ip.strip()) + "%")
    labels = session_labels(store)
    if attack:
        ids = [sid for sid, label in labels.items() if label == attack]
        if not ids:
            return []
        where.append("s.id IN (" + ",".join("?" * len(ids)) + ")")
        args.extend(ids)
    sql = (
        "SELECT s.id, s.started, s.ended, s.src_ip, s.client_version, s.username, s.authed, "
        "(SELECT COUNT(*) FROM events e WHERE e.session_id = s.id AND e.kind = 'command') AS cmds "
        "FROM sessions s" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY s.id DESC LIMIT ? OFFSET ?"
    )
    rows = store.db.execute(sql, (*args, limit, offset)).fetchall()
    out = [dict(r) for r in rows]
    for row in out:
        row["attack"] = labels.get(row["id"])
    return out


def session_events(store, session_id):
    rows = store.db.execute(
        "SELECT ts, kind, data FROM events WHERE session_id = ? ORDER BY id", (session_id,)
    ).fetchall()
    return [{"ts": r["ts"], "kind": r["kind"], "data": json.loads(r["data"])} for r in rows]


ATTACK_RULES = [
    ("майнер", ("xmr", "minerd", "xmrig", "stratum+tcp")),
    ("загрузчик ботнета", ("wget http", "curl -s http", "curl http", "| sh", "tftp", "ftpget")),
    ("захват аккаунта", ("chpasswd", "passwd")),
    ("кража ssh-ключей", (".ssh", "authorized_keys")),
    ("разведка системы", ("uname", "whoami", "cat /etc/passwd", "cpuinfo", "free", "nproc", "ifconfig", "id", "uptime", "df", "ls", "ps", "w")),
]


# Метки, которые бывают у сессий (список в странице дашборда должен совпадать, это проверяет тест).
ATTACK_TYPES = [label for label, _ in ATTACK_RULES] + ["реверс-шелл", "повышение привилегий", "прочее"]


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


def session_labels(store):
    """Тип атаки для каждой сессии, где были команды, реверс-шелл или повышение привилегий."""
    per_session: dict[int, list[str]] = {}
    for sid, _, d in store.events("command"):
        per_session.setdefault(sid, []).append(d["cmd"])
    revshell = {sid for sid, _, _ in store.events("revshell")}
    privesc = {sid for sid, _, _ in store.events("privesc")}
    labels = {}
    for sid in per_session.keys() | revshell | privesc:
        if sid in revshell:
            labels[sid] = "реверс-шелл"
        elif sid in privesc:
            labels[sid] = "повышение привилегий"
        else:
            labels[sid] = classify(per_session[sid])
    return labels


def attacks(store):
    per_session = {sid for sid, _, _ in store.events("command")}
    counter = Counter(session_labels(store).values())
    silent = store.db.execute("SELECT COUNT(*) FROM sessions WHERE authed = 1").fetchone()[0] - len(per_session)
    if silent > 0:
        counter["вошёл и молчит"] += silent
    return [[k, v] for k, v in counter.most_common()]


GROUPS_LIMIT = 20
GROUP_SHOWN_CMDS = 3


def groups(store, limit=GROUPS_LIMIT, min_repeats=2):
    """Повторяющиеся боты: сессии с одним IP, клиентом и набором команд. Считается на лету, в базу ничего не пишется."""
    limit = clamp(limit, 1, 100, GROUPS_LIMIT)
    cmds: dict[int, list[str]] = {}
    for sid, _, d in store.events("command"):
        cmds.setdefault(sid, []).append(d["cmd"])
    found: dict[tuple, dict] = {}
    for sid, started, ip, client in store.db.execute(
        "SELECT id, started, src_ip, client_version FROM sessions WHERE authed = 1"
    ):
        key = (ip, client, tuple(cmds.get(sid, ())))
        g = found.get(key)
        if g is None:
            found[key] = {"ip": ip, "client": client, "cmds": list(key[2]), "n": 1, "first": started, "last": started}
        else:
            g["n"] += 1
            g["first"] = min(g["first"], started)
            g["last"] = max(g["last"], started)
    top_groups = sorted((g for g in found.values() if g["n"] >= min_repeats), key=lambda g: (-g["n"], -g["last"]))
    return top_groups[:limit]


def feed(store, limit=12):
    rows = store.db.execute(
        "SELECT e.ts, e.kind, e.data, s.src_ip FROM events e JOIN sessions s ON s.id = e.session_id "
        "WHERE e.kind IN ('auth', 'command', 'url', 'revshell', 'privesc') ORDER BY e.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    out = []
    for r in rows:
        d = json.loads(r["data"])
        if r["kind"] == "auth":
            text = f"{d['username']}:{d['password']} -> " + ("вход" if d["ok"] else "отказ")
        elif r["kind"] == "command":
            text = d["cmd"]
        elif r["kind"] == "revshell":
            text = f"реверс-шелл → {d['target']} ({d['technique']})"
        elif r["kind"] == "privesc":
            text = f"повышение привилегий: {d['technique']}"
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
    if path == "/api/groups":
        return groups(store, query.get("limit", [None])[0])
    if path == "/api/feed":
        return feed(store)
    if path == "/api/sessions":
        q = lambda k: query.get(k, [None])[0]  # noqa: E731
        return sessions(store, q("limit"), q("offset"), q("ip"), q("attack"))
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
