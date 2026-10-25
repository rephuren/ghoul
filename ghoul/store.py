"""SQLite-хранилище сессий и событий."""
import json
import os
import sqlite3
import time

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

    def event(self, session_id, kind, data):
        self.db.execute(
            "INSERT INTO events (session_id, ts, kind, data) VALUES (?, ?, ?, ?)",
            (session_id, time.time(), kind, json.dumps(data, ensure_ascii=False)),
        )
        self.db.commit()

    def events(self, kind):
        for row in self.db.execute("SELECT session_id, ts, data FROM events WHERE kind = ? ORDER BY id", (kind,)):
            yield row["session_id"], row["ts"], json.loads(row["data"])

    def close(self):
        self.db.close()
