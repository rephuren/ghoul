"""SQLite-хранилище сессий и событий."""
import json
import os
import sqlite3
import time

MAX_FIELD_CHARS = 2000
MAX_EVENTS_PER_SESSION = 2000
DAY = 86400

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started REAL NOT NULL,
    ended REAL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    client_version TEXT,
    username TEXT,
    password TEXT,
    authed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES sessions(id),
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.event_counts = {}

    def open_session(self, src_ip, src_port, client_version=None):
        cur = self.db.execute(
            "INSERT INTO sessions (started, src_ip, src_port, client_version) VALUES (?, ?, ?, ?)",
            (time.time(), src_ip, src_port, client_version),
        )
        self.db.commit()
        return cur.lastrowid

    def close_session(self, session_id):
        self.db.execute("UPDATE sessions SET ended = ? WHERE id = ?", (time.time(), session_id))
        self.db.commit()

    def set_client_version(self, session_id, version):
        self.db.execute("UPDATE sessions SET client_version = ? WHERE id = ?", (version, session_id))
        self.db.commit()

    def log_auth(self, session_id, username, password, ok):
        self.event(session_id, "auth", {"username": username, "password": password, "ok": ok})
        if ok:
            self.db.execute(
                "UPDATE sessions SET username = ?, password = ?, authed = 1 WHERE id = ?",
                (username, password, session_id),
            )
            self.db.commit()

    @staticmethod
    def _clip(data):
        """Ограничивает длинные строковые поля: атакующий не должен раздувать базу."""
        if not isinstance(data, dict):
            return data
        return {k: (v[:MAX_FIELD_CHARS] + "…" if isinstance(v, str) and len(v) > MAX_FIELD_CHARS else v) for k, v in data.items()}

    def event(self, session_id, kind, data):
        count = self.event_counts.get(session_id, 0) + 1
        self.event_counts[session_id] = count
        if count > MAX_EVENTS_PER_SESSION:
            if count == MAX_EVENTS_PER_SESSION + 1:
                self._insert_event(session_id, "event-limit", {"limit": MAX_EVENTS_PER_SESSION})
            return
        self._insert_event(session_id, kind, self._clip(data))

    def _insert_event(self, session_id, kind, data):
        self.db.execute(
            "INSERT INTO events (session_id, ts, kind, data) VALUES (?, ?, ?, ?)",
            (session_id, time.time(), kind, json.dumps(data, ensure_ascii=False)),
        )
        self.db.commit()

    def events(self, kind):
        for row in self.db.execute("SELECT session_id, ts, data FROM events WHERE kind = ? ORDER BY id", (kind,)):
            yield row["session_id"], row["ts"], json.loads(row["data"])

    def prune(self, max_sessions=50000, max_age_days=30, now=None):
        """Удаляет старые сессии (по возрасту и по общему числу) вместе с их событиями. Возвращает число удалённых."""
        cutoff = (now if now is not None else time.time()) - max_age_days * DAY
        old = [r[0] for r in self.db.execute("SELECT id FROM sessions WHERE started < ?", (cutoff,))]
        extra = [r[0] for r in self.db.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT -1 OFFSET ?", (max_sessions,))]
        doomed = sorted(set(old) | set(extra))
        for i in range(0, len(doomed), 500):
            chunk = doomed[i:i + 500]
            marks = ",".join("?" * len(chunk))
            self.db.execute(f"DELETE FROM events WHERE session_id IN ({marks})", chunk)
            self.db.execute(f"DELETE FROM sessions WHERE id IN ({marks})", chunk)
        self.db.commit()
        for sid in doomed:
            self.event_counts.pop(sid, None)
        return len(doomed)

    def close(self):
        self.db.close()
