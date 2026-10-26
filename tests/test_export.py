import csv
import io
import json

import pytest

from ghoul import export
from ghoul.__main__ import main
from ghoul.store import Store

NOW = 1_800_000_000.0


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "e.db"))
    a = s.open_session("203.0.113.5", 4000)
    b = s.open_session("198.51.100.7", 4001)
    for sid, ts, kind, data in [
        (a, NOW - 100, "auth", {"username": "root", "password": "123456", "ok": False}),
        (a, NOW - 90, "command", {"cmd": "uname -a"}),
        (b, NOW - 8 * 86400, "command", {"cmd": "id"}),
        (b, NOW - 10, "url", {"url": "http://203.0.113.9/x.sh"}),
    ]:
        s.db.execute("INSERT INTO events (session_id, ts, kind, data) VALUES (?, ?, ?, ?)", (sid, ts, kind, json.dumps(data, ensure_ascii=False)))
    s.db.commit()
    return s


def test_parse_since_units_and_errors():
    assert export.parse_since("30m") == 1800
    assert export.parse_since("12h") == 43200
    assert export.parse_since("7d") == 7 * 86400
    assert export.parse_since(" 2W ") == 14 * 86400
    for bad in ["", "7", "d", "0d", "-1d", "7 days", "1000000d", "7y", None]:
        with pytest.raises(ValueError):
            export.parse_since(bad)


def test_neutralize_formula_starts():
    for s in ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tтаб", "\rперевод", "\nстрока"]:
        assert export.neutralize(s).startswith("'")
    assert export.neutralize("обычный текст") == "обычный текст"
    assert export.neutralize("a=b") == "a=b"
    assert export.neutralize(None) == ""
    assert export.neutralize(5) == "5"


def test_rows_all_filters_and_order(store):
    items = list(export.rows(store, now=NOW))
    assert [i["kind"] for i in items] == ["auth", "command", "command", "url"]
    assert items[0]["src_ip"] == "203.0.113.5" and items[0]["data"]["username"] == "root"
    assert len(list(export.rows(store, since_seconds=86400, now=NOW))) == 3  # недельное событие отфильтровано
    assert [i["kind"] for i in export.rows(store, kinds=["url", "auth"], now=NOW)] == ["auth", "url"]
    assert list(export.rows(store, kinds=["нет-такого"], now=NOW)) == []


def test_kind_filter_is_not_sql_injection(store):
    assert list(export.rows(store, kinds=["x') OR 1=1 --"], now=NOW)) == []
    assert store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 4


def test_json_is_valid_and_empty_is_valid(store):
    buf = io.StringIO()
    export.write_json(export.rows(store, now=NOW), buf)
    assert len(json.loads(buf.getvalue())) == 4
    empty = io.StringIO()
    export.write_json(iter(()), empty)
    assert json.loads(empty.getvalue()) == []


def test_csv_quotes_newlines_commas_and_neutralizes_formulas(store):
    s = store
    sid = s.open_session("=HYPERLINK(\"http://203.0.113.1\")", 1)
    nasty = {"cmd": '=cmd|\' /C calc\'!A0', "note": 'a, "quoted"\nline2'}
    s.db.execute("INSERT INTO events (session_id, ts, kind, data) VALUES (?, ?, ?, ?)", (sid, NOW, "command", json.dumps(nasty, ensure_ascii=False)))
    s.db.commit()
    buf = io.StringIO()
    export.write_csv(export.rows(s, kinds=["command"], now=NOW), buf)
    parsed = list(csv.reader(io.StringIO(buf.getvalue())))
    assert parsed[0] == export.COLUMNS
    last = parsed[-1]
    assert last[2].startswith("'=")  # адрес источника не превращается в формулу
    assert not any(cell.startswith(("=", "+", "-", "@")) for row in parsed[1:] for cell in row)
    assert json.loads(last[4].lstrip("'")) == nasty  # данные восстанавливаются целиком после снятия апострофа


def test_cli_export_json_csv_and_errors(store, tmp_path, capsys):
    db = str(tmp_path / "e.db")
    main(["export", "--db", db, "--format", "json", "--kind", "command"])
    out = json.loads(capsys.readouterr().out)
    assert {i["kind"] for i in out} == {"command"}
    target = tmp_path / "out.csv"
    main(["export", "--db", db, "--format", "csv", "--since", "7d", "--out", str(target)])
    assert "выгрузка записана" in capsys.readouterr().err
    assert len(target.read_text(encoding="utf-8").strip().split("\n")) >= 2
    with pytest.raises(SystemExit) as e:
        main(["export", "--db", db, "--since", "вчера"])
    assert e.value.code == 2
