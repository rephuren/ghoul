"""Выгрузка событий в JSON и CSV для анализа вне дашборда.
Данные в базе пишут атакующие, поэтому CSV защищён от «формул»: ячейка, начинающаяся с = + - @, при открытии в таблице выполнилась бы."""
import csv
import json
import re
import time
from datetime import datetime, timezone

UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")
COLUMNS = ["time", "session", "src_ip", "kind", "data"]


def parse_since(text):
    """«30m», «12h», «7d», «2w» в секунды. Неверная запись даёт ValueError."""
    m = re.fullmatch(r"(\d{1,6})([mhdw])", (text or "").strip().lower())
    if not m or int(m.group(1)) == 0:
        raise ValueError(f"--since {text!r}: ожидается число и единица, например 30m, 12h, 7d, 2w")
    return int(m.group(1)) * UNITS[m.group(2)]


def neutralize(value):
    """Не даёт ячейке стать формулой: добавляет апостроф, который таблицы показывают как обычный текст."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(FORMULA_START) else s


def rows(store, since_seconds=None, kinds=None, now=None):
    """События с адресом источника. Фильтры идут параметрами запроса, а не подстановкой в SQL."""
    sql = ("SELECT e.ts, e.session_id, s.src_ip, e.kind, e.data FROM events e JOIN sessions s ON s.id = e.session_id")
    where, params = [], []
    if since_seconds is not None:
        where.append("e.ts >= ?")
        params.append((now if now is not None else time.time()) - since_seconds)
    if kinds:
        where.append(f"e.kind IN ({','.join('?' * len(kinds))})")
        params.extend(kinds)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY e.id"
    for r in store.db.execute(sql, params):
        yield {
            "time": datetime.fromtimestamp(r["ts"], tz=timezone.utc).isoformat(timespec="seconds"),
            "session": r["session_id"],
            "src_ip": r["src_ip"],
            "kind": r["kind"],
            "data": json.loads(r["data"]),
        }


def write_json(items, fh):
    fh.write("[")
    for i, item in enumerate(items):
        fh.write(("," if i else "") + "\n  " + json.dumps(item, ensure_ascii=False))
    fh.write("\n]\n")


def write_csv(items, fh):
    w = csv.writer(fh, lineterminator="\n")
    w.writerow(COLUMNS)
    for item in items:
        w.writerow([
            neutralize(item["time"]), item["session"], neutralize(item["src_ip"]), neutralize(item["kind"]),
            neutralize(json.dumps(item["data"], ensure_ascii=False)),
        ])
